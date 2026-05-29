from prometheus_client import multiprocess


def child_exit(server, worker):
  del server
  multiprocess.mark_process_dead(worker.pid)
