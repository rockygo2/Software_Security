set logging file /dev/null
set logging redirect on
set logging enabled on
# For this challenge, please replace any occurence of `<TODO>` after this line with your answer. 
# There is no need to change anything else, unless otherwise specified.
# Make sure that the final script contains valid GDB commands before submitting, 
# and that it works properly, by running `gdb decoder --batch -x script.gdb`.


# This binary requires a password that is encoded within the binary.
# The binary only decodes a single byte of the password at once. 
# Because of this, the entire decoded password is never loaded into memory.
# Thus, we will need to read the decoded password byte-by-byte.


# [Part 1]

# [1.1] The start of the program contains a check that reveals the length the password is supposed to be.
# What is the length of the password according to this check?
set $password_length = 20

# [1.2] In which variable is the encoded password stored?
set $encoded_password = encoded

# [1.3] Which function decodes a part of the password?
set $decode_function = decode


# [Part 2]

# [2.1] To read a byte of the password, we need to set a breakpoint just after a byte is decoded.
# Set a breakpoint immediately after the `decode_function` returns back to `main`.
break *main+118
commands
    set logging enabled off

# [2.2] We want to print each decoded byte to the terminal, so that we can reconstruct the entire password.
# Add commands that run each time the breakpoint is triggered to print the decoded bytes. 
# Make sure to print them as a character, using `printf`, and without newlines or other characters in between.

    set $char = $rax
    printf "%c", $char

    set logging enabled on
    continue
end


# [Part 3]

# [3.1] Now that we have set a breakpoint, run the program in a way that will reveal the first character of the password.

run AAAAAAAAAAAAAAAAAAA

echo \n

# [3.2] By repeating this, we can slowly find the entire password.
# Find the password, and run the program once more with the entire password as argument.
run flag{H4shItN3xtT1me}

