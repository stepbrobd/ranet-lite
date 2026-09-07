{ pkgs }:

# iperf 3.21's GRO receive uses MSG_DONTWAIT inside a worker loop that never
# waits for readiness. Eight bidirectional streams can therefore occupy all
# CPUs even on an idle link, starving a tunnel on the same machine. Match the
# ordinary UDP receiver's blocking behavior; pthread cancellation still stops
# each worker when the test ends.
pkgs.iperf3.overrideAttrs (old: {
  postPatch = (old.postPatch or "") + ''
    substituteInPlace src/net.c \
      --replace-fail 'recvmsg(fd, &msg, MSG_DONTWAIT)' 'recvmsg(fd, &msg, 0)'
  '';
})
