> A wordlist generator where you can specify a standard character set or any set of characters to be used in generating the wordlists. 
> 
> The wordlists are created through combination and permutation of a set of characters. You can determine the amount of characters and list size.
> 
> This program supports numbers and symbols, upper and lower case characters separately and Unicode.


#Password_Attacks 

# Usage

Generating a wordlist for a bruteforce attack
```bash
crunch 6 6 -t somepword%%% > wordlist
```
- `6 6` minimum and maximum length of 6
- `-t` option specifies a custom pattern `somepword%%%` for generating words
	- `%` is a placeholder character that will be replaced by characters during the wordlist generation

Generating a wordlist for a bruteforce attack
```bash
crunch 6 6 0123456789abcdef -o 6chars.tx
```
- `6 6` minimum and maximum length of 6
- `0123456789abcdef` using these given characters
- `-o 6chars.txt` saving the output to a file