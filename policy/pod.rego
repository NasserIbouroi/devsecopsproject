package main

deny[msg] {
  input.kind == "Pod"
  container := input.spec.containers[_]
  not container.securityContext.runAsNonRoot
  msg = sprintf("Container '%v' is running as root or missing 'runAsNonRoot'", [container.name])
}
