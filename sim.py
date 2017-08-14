# ------------------------------------------------------------------
# CS620 Operating System Principles for Information Assurance
# Mark Moss: Saturday, September 13th, 2014
# Programming Assignment 4 - Scheduling & Performance
# ------------------------------------------------------------------
import random
import heapq
 
CPU_POLICY, CPU_QUANTUM = 'fcfs', 3
MEMORY_POLICY, MEMORY_FRAMES = 'fifo', 10
PROCESS_SEQ, PAGE_SEQ = [], []

# ------------------------------------------------------------------
# The newseq() and newproc() functions generate a sequence of
# processes and associated page requests
# ------------------------------------------------------------------

def newproc(pid, clock, category):
  working_sets = [[0, 9, 2, 5], [10, 19, 1, 3], [20, 29, 1, 3], [30, 39, 1, 3], [40, 79, 2, 5], [80, 99, 4, 15]]

  # calculate the duration and page requests for this process
  pages = working_sets[category]
  duration = random.randint(pages[2], pages[3])
  anchor = random.randint(pages[0], pages[1] - duration)

  # format: [process identifier, arrival time, [page requests]]
  return [pid, clock, list(range(anchor, anchor + duration))]

def newseq(size):
  categories = [[6, 3, 3, 3, 4, 2], [5, 2, 2, 2, 8, 5], [4, 5, 5, 5, 2, 1]]
  transitions = [3, 5, 8]
  clock, pid, state, result = 0, 0, 0, []

  # generate 0 or more new processes for each time slot
  for i in range(size):
    cycle = categories[state]

    # generate process types: OS, user, web & database
    for j, proc_check in enumerate(cycle):
      if random.randint(0, 9) <= proc_check:
        result.append(newproc(pid, clock, j))
        pid = pid + 1

    # determine whether to advance process cycle
    if random.randint(0, 9) <= transitions[state]:
      state = (state + 1) % 3

    # advance the clock for the next cycle of processes
    clock = clock + 1

  # return the process sequence
  return result

def generate(size):
  global PROCESS_SEQ
  PROCESS_SEQ = newseq(size)

def run():
  global PROCESS_SEQ, PAGE_SEQ

  (PAGE_SEQ, responses, waits, count) = cpu_mechanism(PROCESS_SEQ)
  faults = memory_mechanism(PAGE_SEQ)

  # return the comprehensive statistics for this sequence
  return responses, waits, count, faults

def cpu_mechanism(processes):
  active, arrivals, waiting, clock = [], [], processes[:], 0
  total_procs, total_wait, total_response, page_sequence = 0, 0, 0, []

  # iterate through the process sequence
  while active or waiting:
    # identify the new processes based on the current clock
    arrivals = [proc for proc in waiting if proc[1] <= clock]
    waiting = [proc for proc in waiting if proc[1] > clock]

    # insert arrivals to the active queue
    for proc in arrivals:
      pid, arrived, pages = proc
      priority = cpu_prioritize(arrived, pages, active)
      heapq.heappush(active, [priority, pid, arrived, None, pages])

    # select the next process to be executed
    if active:
      selected = heapq.heappop(active)
      priority, pid, arrived, started, pages = selected
      if not started:
        started = clock
    else:
      clock = min([proc[2] for proc in waiting]) 
      continue

    # determine duration for the selected process
    duration, remainder = cpu_schedule(pages)

    # assemble the page request sequence
    page_sequence.extend(duration)

    # collect the performance statistics iff the process finished
    if not remainder:
      total_procs, stopped = total_procs + 1, clock + len(duration)
      total_wait = total_wait + (started - arrived)
      total_response = total_response + (stopped - arrived)

    # re-insert the remining process iff necessary
    if remainder:
      priority = cpu_prioritize(arrived, remainder, active)
      heapq.heappush(active, [priority, pid, arrived, started, remainder])

    # advance the clock
    clock = clock + len(duration)

  # return the sequence of page requests and cpu statistics
  return (page_sequence, total_response, total_wait, total_procs)

def cpu_prioritize(arrived, pages, active):
  global CPU_POLICY

  if CPU_POLICY == 'fcfs':
    return arrived
  elif CPU_POLICY == 'sjf':
    return len(pages)
  elif CPU_POLICY == 'rr':
    if active:
      return max([proc[0] for proc in active]) + 1
    else:
      return 0
  elif CPU_POLICY == 'rand':
    return random.randint(0, 1000)
  else: # default of 'fcfs'
    return arrived
  
def cpu_schedule(pages):
  global CPU_POLICY, CPU_QUANTUM

  pages_copy = pages[:]
  if CPU_POLICY in ['fcfs', 'sjf', 'rand']:
    return pages_copy, []
  elif CPU_POLICY == 'rr':
    return pages_copy[:CPU_QUANTUM], pages_copy[CPU_QUANTUM:]
  else: # default of 'fcfs'
    return pages_copy, []
    
def memory_mechanism(page_requests):
  global MEMORY_FRAMES

  frames, page_stream = dict(), page_requests[:]
  capacity, faults, clock, victim_ptr = 0, 0, 0, 0

  # iterate through the page request sequence
  for page in page_stream:

    # bring pages not in memory into a free frame
    if page not in frames:
      if capacity < MEMORY_FRAMES:
        frames[page] = [clock, clock, capacity, False]
        capacity = capacity + 1
      else:
        faults = faults + 1
        victim, victim_ptr = memory_target(frames, victim_ptr)
        frames[page] = [clock, clock, victim_ptr, True]
        del frames[victim]

    # update the statistics for pages already in memory
    else:
      frames[page][1], frames[page][2] = clock, True

    # advance the clock
    clock = clock + 1

  # return the memory statistics
  return faults

def memory_target(frames, victim_ptr):
  global MEMORY_POLICY, MEMORY_FRAMES

  candidates = []
  if MEMORY_POLICY == 'lru':
    for key, value in frames.items():
      candidates.append([value[1], key])
    candidates.sort()
    return candidates[0][1], 0
  elif MEMORY_POLICY == 'mru':
    for key, value in frames.items():
      candidates.append([value[1], key])
    candidates.sort()
    candidates.reverse()
    return candidates[0][1], 0
  elif MEMORY_POLICY == 'clock':
    for key, value in frames.items():
      candidates.append([value[2], value[3], key])
    candidates.sort()
    while candidates[victim_ptr][1]:
      candidates[victim_ptr][1] = False
      victim_ptr = (victim_ptr + 1) % len(candidates)
    return candidates[victim_ptr][2], victim_ptr
  elif MEMORY_POLICY == 'rand':
    for key, value in frames.items():
      candidates.append([random.randint(0, 1000), key])
    candidates.sort()
    return candidates[0][1], 0
  else: # default is 'fifo'
    for key, value in frames.items():
      candidates.append([value[0], key])
    candidates.sort()
    return candidates[0][1], 0


