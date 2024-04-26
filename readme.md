# Integer Overflows Sniper

As part of an exercise related to techniques and strategies of application code review, I decided to write some simple mechanism to check where integer overflow type errors occur. Just for fun & profit (maybe)!

<p>
<img width="150" height="150" src="https://raw.githubusercontent.com/qilingframework/qiling/master/docs/qiling2_logo_small.png">
</p>

The script is based on the Qiling framework and it performs a simple algorithm. It performs modulo operations for the register values used in the “add” and “mul” instructions.

Now imagine that we have an instruction of this type:

```sh
105b0 [66992] add r3, r2, r3 # -> r3 = r3 + r2
```

We have the following register values:

`R2 = 0xe0000020` # The value set earlier in the running program.

`R3 = 0x20000012` # Value passed to the program

The 'add' instruction sums the two register values (R2 + R3) and then places the result in the R3 register.

Knowing the value passed to the program during fuzzing and the value in the second register, we can perform a modulo operation and check if the result from modulo is in the given register.
If it is - overflow exists.

```sh
(0xe0000020 + 0x20000012) % 10000000
```

Enjoy! ;>
