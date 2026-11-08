/* PAM-olive test-only loopback RDP peer. No OS account, shell or desktop.
 * Built against public FreeRDP/WinPR APIs; never copied into production.
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
#define _GNU_SOURCE
#include <freerdp/peer.h>
#include <freerdp/freerdp.h>
#include <freerdp/primary.h>
#include <freerdp/crypto/certificate.h>
#include <freerdp/crypto/privatekey.h>
#include <freerdp/settings.h>
#include <winpr/ntlm.h>
#include <winpr/ssl.h>
#include <winpr/synch.h>
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/syscall.h>
#include <unistd.h>

typedef struct {
    rdpContext context;
    int authenticated;
    int redirect;
} FixtureContext;

typedef struct {
    int socket_fd;
    const char* cert_path;
    const char* key_path;
    const char* sam_path;
    int redirect_mode;
} PeerArguments;

static BOOL context_new(freerdp_peer* peer, rdpContext* context) {
    (void)peer; (void)context;
    return TRUE;
}

static void event(const char* kind) {
    char line[128];
    int length = snprintf(line, sizeof(line), "{\"event\":\"%s\",\"connection\":%ld}\n", kind, syscall(SYS_gettid));
    if (length > 0 && (size_t)length < sizeof(line))
        (void)write(STDOUT_FILENO, line, (size_t)length);
}

static BOOL paint(rdpContext* context, UINT32 color) {
    OPAQUE_RECT_ORDER rectangle = {0};
    rectangle.nLeftRect = 0;
    rectangle.nTopRect = 0;
    rectangle.nWidth = 320;
    rectangle.nHeight = 200;
    rectangle.color = color;
    rdpUpdate* update = context->update;
    return update->BeginPaint(context)
        && update->primary->OpaqueRect(context, &rectangle)
        && update->EndPaint(context);
}

static BOOL activate(freerdp_peer* peer) {
    FixtureContext* context = (FixtureContext*)peer->context;
    event("activated");
    if (context->redirect) {
        rdpRedirection* redirect = redirection_new();
        if (!redirect)
            return FALSE;
        BOOL ready = redirection_set_flags(redirect, LB_TARGET_NET_ADDRESS)
            && redirection_set_session_id(redirect, 1)
            && redirection_set_string_option(redirect, LB_TARGET_NET_ADDRESS, "127.0.0.2");
        BOOL sent = ready && peer->SendServerRedirection(peer, redirect);
        redirection_free(redirect);
        if (sent)
            event("redirect_sent");
        return sent;
    }
    return paint(peer->context, 0x2e4128);
}

static BOOL post_connect(freerdp_peer* peer) {
    FixtureContext* context = (FixtureContext*)peer->context;
    /* PostConnect is reached only after the enabled CredSSP exchange. */
    if (!peer->authenticated)
        return FALSE;
    context->authenticated = 1;
    event("authenticated");
    return TRUE;
}

static BOOL logon(freerdp_peer* peer, const SEC_WINNT_AUTH_IDENTITY* identity, BOOL automatic) {
    (void)identity;
    rdpSettings* settings = peer->context->settings;
    if (!automatic || !freerdp_settings_get_bool(settings, FreeRDP_NlaSecurity))
        return FALSE;
    /* FreeRDP 3.15 stores decrypted TSPasswordCreds in settings, not in the
     * legacy auth-identity argument. NTLM proof was checked against our SAM
     * before this callback. Require the complete delegated credentials too. */
    const char* username = freerdp_settings_get_string(settings, FreeRDP_Username);
    const char* domain = freerdp_settings_get_string(settings, FreeRDP_Domain);
    const char* password = freerdp_settings_get_string(settings, FreeRDP_Password);
    BOOL valid = username && domain && password
        && strcmp(username, "fixture") == 0 && strcmp(domain, "FIXTURE") == 0
        && strcmp(password, getenv("PAM_TEST_PASSWORD")) == 0;
    if (valid)
        event("nla_verified");
    return valid;
}

static BOOL keyboard(rdpInput* input, UINT16 flags, UINT8 code) {
    if (!(flags & KBD_FLAGS_RELEASE) && code == 0x1e) {
        event("key_a");
        return paint(input->context, 0x58d8bb);
    }
    return TRUE;
}

static BOOL unicode_key(rdpInput* input, UINT16 flags, UINT16 code) {
    if (!(flags & KBD_FLAGS_RELEASE) && code == 'a') {
        event("key_a");
        return paint(input->context, 0x58d8bb);
    }
    return TRUE;
}

static BOOL synchronize(rdpInput* input, UINT32 flags) {
    (void)input; (void)flags;
    return TRUE;
}

static BOOL mouse(rdpInput* input, UINT16 flags, UINT16 x, UINT16 y) {
    (void)input; (void)flags; (void)x; (void)y;
    return TRUE;
}

static void* serve(void* pointer) {
    PeerArguments arguments = *(PeerArguments*)pointer;
    free(pointer);
    freerdp_peer* peer = freerdp_peer_new(arguments.socket_fd);
    if (!peer) {
        close(arguments.socket_fd);
        return NULL;
    }
    peer->ContextSize = sizeof(FixtureContext);
    peer->ContextNew = context_new;
    if (!freerdp_peer_context_new(peer)) {
        event("context_failed");
        freerdp_peer_free(peer);
        return NULL;
    }
    FixtureContext* context = (FixtureContext*)peer->context;
    context->redirect = arguments.redirect_mode;
    rdpSettings* settings = peer->context->settings;
    rdpPrivateKey* key = freerdp_key_new_from_file(arguments.key_path);
    rdpCertificate* cert = freerdp_certificate_new_from_file(arguments.cert_path);
    if (!key || !cert)
        goto cleanup;
    if (!freerdp_settings_set_pointer_len(settings, FreeRDP_RdpServerRsaKey, key, 1)
        || !freerdp_settings_set_pointer_len(settings, FreeRDP_RdpServerCertificate, cert, 1)
        || !freerdp_settings_set_bool(settings, FreeRDP_NlaSecurity, TRUE)
        || !freerdp_settings_set_bool(settings, FreeRDP_TlsSecurity, FALSE)
        || !freerdp_settings_set_bool(settings, FreeRDP_RdpSecurity, FALSE)
        || !freerdp_settings_set_string(settings, FreeRDP_NtlmSamFile, arguments.sam_path)
        || !freerdp_settings_set_uint32(settings, FreeRDP_DesktopWidth, 640)
        || !freerdp_settings_set_uint32(settings, FreeRDP_DesktopHeight, 480)
        || !freerdp_settings_set_uint32(settings, FreeRDP_ColorDepth, 32)
        || !freerdp_settings_set_bool(settings, FreeRDP_RemoteFxCodec, FALSE)
        || !freerdp_settings_set_bool(settings, FreeRDP_NSCodec, FALSE)
        || !freerdp_settings_set_bool(settings, FreeRDP_SupportGraphicsPipeline, FALSE))
        goto cleanup;
    peer->PostConnect = post_connect;
    peer->Logon = logon;
    peer->Activate = activate;
    peer->context->input->KeyboardEvent = keyboard;
    peer->context->input->UnicodeKeyboardEvent = unicode_key;
    peer->context->input->SynchronizeEvent = synchronize;
    peer->context->input->MouseEvent = mouse;
    peer->context->input->ExtendedMouseEvent = mouse;
    if (peer->Initialize(peer)) {
        event("peer_ready");
        for (;;) {
            HANDLE events[32];
            DWORD count = peer->GetEventHandles(peer, events, 32);
            if (!count)
                break;
            DWORD status = WaitForMultipleObjects(count, events, FALSE, 1000);
            if (status == WAIT_FAILED || !peer->CheckFileDescriptor(peer))
                break;
        }
    }
    if (context->authenticated)
        event("disconnected");
    peer->Disconnect(peer);
cleanup:
    freerdp_peer_context_free(peer);
    freerdp_peer_free(peer);
    return NULL;
}

int main(int argc, char** argv) {
    if (argc != 5)
        return 2;
    if (!winpr_InitializeSSL(WINPR_SSL_INIT_DEFAULT))
        return 14;
    WSADATA winsock = {0};
    if (WSAStartup(MAKEWORD(2, 2), &winsock))
        return 15;
    const char* password = getenv("PAM_TEST_PASSWORD");
    if (!password || !*password || strlen(password) > 128)
        return 3;
    BYTE hash[16];
    if (!NTOWFv1A((char*)password, (UINT32)strlen(password), hash))
        return 4;
    int sam = open(argv[3], O_CREAT | O_EXCL | O_WRONLY, 0600);
    if (sam < 0)
        return 5;
    char row[100] = "fixture:FIXTURE::";
    size_t prefix = strlen(row);
    for (size_t index = 0; index < sizeof(hash); index++)
        (void)snprintf(row + prefix + 2 * index, 3, "%02X", hash[index]);
    (void)strcat(row, ":\n");
    if (write(sam, row, strlen(row)) != (ssize_t)strlen(row))
        return 6;
    close(sam);
    int listener = socket(AF_INET, SOCK_STREAM, 0);
    if (listener < 0)
        return 7;
    struct sockaddr_in address = {0};
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (bind(listener, (struct sockaddr*)&address, sizeof(address)) || listen(listener, 16))
        return 8;
    socklen_t length = sizeof(address);
    if (getsockname(listener, (struct sockaddr*)&address, &length))
        return 9;
    printf("{\"event\":\"ready\",\"port\":%u}\n", ntohs(address.sin_port));
    fflush(stdout);
    signal(SIGPIPE, SIG_IGN);
    for (;;) {
        int incoming = accept(listener, NULL, NULL);
        if (incoming < 0) {
            if (errno == EINTR)
                continue;
            break;
        }
        PeerArguments* arguments = calloc(1, sizeof(PeerArguments));
        if (!arguments) {
            close(incoming);
            continue;
        }
        arguments->socket_fd = incoming;
        arguments->cert_path = argv[1];
        arguments->key_path = argv[2];
        arguments->sam_path = argv[3];
        arguments->redirect_mode = strcmp(argv[4], "redirect") == 0;
        pthread_t thread;
        if (pthread_create(&thread, NULL, serve, arguments)) {
            close(incoming);
            free(arguments);
        } else
            pthread_detach(thread);
    }
    close(listener);
    return 0;
}
