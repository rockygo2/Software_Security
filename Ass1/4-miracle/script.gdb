set logging file /dev/null
set logging redirect on
set logging enabled on
# For this challenge, please replace any occurence of `<TODO>` after this line with your answer. 
# There is no need to change anything else, unless otherwise specified.
# Make sure that the final script contains valid GDB commands before submitting, 
# and that it works properly, by running `gdb miracle --batch -x script.gdb`.

# This binary implements a new state-of-the-art, bleeding edge, innovative algorithm used for 
# authentication that is way faster than what's currently used in industry. The basis of this
# algorithm stems from the sorting algorithm called "Miracle sort". Recall the aforementioned algorithm:
#
# 1) Check if the array is sorted.
# 2) If it is not sorted, then go to step 1.
#
# Similarly, the authentication algorithm used here is:
#
# if (true)
#     reject
# else
#     accept

# The exploitation is straight-forward, we want to flip the condition that checks authentication.
# After compilation, the assembly instruction that does so looks like this:
# <location>    cmp  <constant>, %eax       # as instruction
# <location>    0x3d <constant>             # as bytes

# Our objective is to find <location>, find the actual value of %eax, then replace <location + 1>
# with the value of %eax at the point of comparison.

# Before reading any further, run the binary in GDB by yourself and explore the program for a bit.
# Try to run the program only in small steps at a time (so, using `continue/step x` with x some initially
# small values, then some larger values). This should give you an idea on the difficulty of this
# challenge.

# [Part 1] 
# Manual method

# [1.1]: You might have noticed that the program is very repetitive. Find a suitable 
# breakpoint that will help you with exploring the program.
break *0x401060

# Now, try to run the program so that we get to the interesting part, that is, the authentication
# condition. This is the big step where you have to skip through all the garbage. Find the number of
# breakpoint triggers to skip so that you land right before the authentication condition.
# Adjust yourself in such a way that you're actually in the authentication function, and not in 
# another function. You may replace the last TODO with only one command.
run test test
continue 9083
ni 23

# Now that $rip is somewhere in the authenticate() function, somewhere
# before the condition, we can try to run assembly instructions by hand until we land on the
# desired assembly instruction. 

# [1.2]: Now it's time to apply the exploit. What is the memory location of the current instruction?
# What is the memory location of the integer that we want to modify? What do we want to replace the 
# condition integer with? You may not hardcode the addresses. You may hardcode the condition integer,
# but you should explain in the `readme.txt` how you got said value.
set $instruction_location = $rip
set $exploited_int_location = $rip + 0xd717 + 6
set $condition_int = 0x1020304

# Apply the exploit.
set *(int*)($exploited_int_location) = $condition_int

# At this point, check the memory again to make sure that only the integer that you want to change
# is changed. Check that GDB can properly parse the cmp instruction as a cmp. If this works,
# then after running the program normally, without any intervention, you should see that 
# you are authenticated.

disable 1
continue


# [Part 2]
# Finding the distinguished location quickly

# [2.1]: Using conditionals, you can figure out how to distinguish the function that you're 
# looking for from the others. The break that you use here must be triggered only once. You may replace 
# the second <TODO> with at most command. Said command must not be similar to the previous method, so any
# instruction of type `continue <magic>` or `s <magic>` is forbidden. In principle, method 2 must work
# regardless of where the comparison is.
break *0x401060 if *(unsigned long*)$rsp == 0x46b91f

# Run the program and adjust so that you can look around authentication. You may replace the second
# <TODO> with at most one command. Similarly to the previous step, the second <TODO> must not use 
# some magic constant.
run test test
finish

# [2.2]: Now it's time to apply the exploit again.
set $instruction_location = $rip
set $exploited_int_location = $rip + 0xd717 + 6
set $condition_int = 0x1020304

# It may be that after the `break` from this method, you're after the comparison, so you may want to
# restart the program. We will add a break to the main function, so that we can apply the exploit before
# going through the authentication procedure.
run test test

# Apply the exploit.
set *(int*)($exploited_int_location) = $condition_int
continue
