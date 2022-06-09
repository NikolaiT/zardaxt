import _thread

def test(data):
  data += 1
  print(data)

thread = _thread.start_new_thread(test, (0, ))

thread.join()