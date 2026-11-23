BEGIN {
  status[1] = "PASS"
  status[2] = "FAIL"
  status[3] = "XFAIL"
  status[4] = "XPASS"
  status[5] = "UNSUPPORTED"
  status[6] = "UNRESOLVED"
  for (i = 1; i <= 6; i++) count[status[i]] = 0
}

/^[A-Z]+: / {
  label = substr($1, 1, length($1) - 1)
  if (!(label in count)) unexpected++
  count[label]++
  if (label != "PASS") print "suite." flavour ".detail=" $0
}

END {
  if (!count["PASS"] || unexpected) exit 1
  for (i = 1; i <= 6; i++)
    print "suite." flavour "." status[i] "=" count[status[i]]
  failed = count["FAIL"] || count["XPASS"] || count["UNRESOLVED"]
  print "suite." flavour ".result=" (failed ? "reported_failures" : "no_unexpected_failures")
}
