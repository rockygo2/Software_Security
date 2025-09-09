set logging file /dev/null
set logging redirect on
set logging enabled on
# For this challenge, please replace any occurence of `<TODO>` after this line with your answer. 
# There is no need to change anything else, unless otherwise specified.
# Make sure that the final script contains valid GDB commands before submitting, 
# and that it works properly, by running `gdb scheduler --batch -x script.gdb`.

# This program helps processing a sequence of orders in a very large factory. At each moment in time,
# the factory receives an order that happens in a certain room. There are also 40 workers, numbered
# from 2 to 41. If an order happens at room `R`, then all robots `i` such that `R mod i == 0` are 
# scheduled to resolve the order at said room. A room can contain at most 8 robots, so if during
# an order, there are more than 8 robots in the same room, then the order must be aborted and the
# incident must be reported.

# The gist of the program is that every once in a while, the program is vulnerable. At each
# step, we have to put some input just to get the program running, which is uninteresting.
# Then, when we find out that the program is vulnerable, we send the payload.

# [Part 1]
# Automating input

# [1.1]: For each step, we're required to add some manual input. We could either put the input in some
# file and then pipe the file to stdin. We will explore this option later. The other option is
# to stop at the function that takes the input, skip it, and also put some input in the read string
# to emulate the reading step. A reason why we choose this is that the number of uninteresting inputs
# is nondeterministic, so it may vary. If we were to pipe a file to the input, we would have had to 
# know the number of uninteresting steps beforehand.
#
# Let's start with putting a breakpoint on the function that reads from the keyboard. There are multiple ways
# in which we can put a breakpoint. We can put a breakpoint either in the source code or on the function fgets
# itself. We may also put a breakpoint on a specific assembly instruction. You might find that one of the methods 
# is more useful than the other.

break *main+192
# Now we want to skip the reading part and emulate the reading step automatically.
# To skip the fgets function, one way that you can do this is to change the instruction pointer manually.
# Find out how many instruction bytes you have to skip to go over the entire fgets call without skipping too much.
commands
    set $offset = 5
    set $rip = $rip + $offset

    # We want to emulate the reading part, so put into buffer a string that is plausible to have been read
    # by fgets.
    set main::buffer = "Test"

    # Now that we have skipped the fgets and emulated it with gdb, the program is still stopped, so we should 
    # keep it going. You may replace this TODO with only one command.
    continue
end
# Finally, to check that our breakpoint actually works, let's run the program to see if it goes until the end.
#r



# [Part 2]
# Finding the perfect moment for exploitation

# [2.1]: Now that we can skip the uninteresting fgets calls, we now have to detect when we're going to have
# an interesting fgets call. To figure this out, when the room is announced (i.e. it is generated), we can
# already figure out if it is going to be an interesting call or not.
#
# We are going to watch a condition of type "room is interesting". Implementing the entire procedure to check
# if a room is interesting might be more complicated. What we can do on the other hand is to take a weaker
# condition that might skip on some of the interesting rooms, but is way easier to implement (that is, it's
# a one-liner).
#
# Thus, if we watch the condition "room is interesting", most of the times it's going to be false, until 
# its value changes (from false, it becomes true), thus the watch point will trigger and stop the execution
# of the program. Therefore, find such a condition to check if a room is interesting.
#
# Hint: For which rooms are robots 2, 3, 4, ..., 9 going to be activated?v
watch contention > 8

# Now that hopefully everything is set up, it's time to run the program. The plan is that the breakpoint
# is going to skip through all the irrelevant user inputs and the watchpoint is going to catch the interesting
# request.
#
# When the interesting request is caught, then we want to feed the exploit to stdin. The payload is given 
# conveniently in the file `payload.txt`, which we will want to pipe to stdin. Then run the program until
# you encounter the interesting room. Make sure that you did not modify the payload.txt file in any way.
# If you did, you can always redownload it. You may replace the second TODO with at most two instructions.
run < payload.txt

# [2.2]: GDB should be somewhere before fgets. Now we want the input from stdin to actually go through, so
# we do not want to skip this particular call of fgets. We should temporarily disable the breakpoint.
# Then, after the breakpoint is disabled, we can feed the payload to the program. You may replace 
# the second TODO with only one instruction.
disable 1
c
# [2.3]: The exploit has been applied. Now we just want to execute the program normally until the very end.
# To do so, we must adjust all the breakpoints/watchpoints. You may replace this TODO with as many 
# `enable`/`disable` instructions as you want and at most one other instruction.
enable 1
disable 2 
c