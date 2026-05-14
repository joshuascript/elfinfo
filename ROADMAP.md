# elfinfo — Roadmap

## 2. Internal call resolution in assembly

Direct `call` instructions to intra-binary addresses (e.g., `call 146a7cf`) currently show the raw hex target. These should be resolved against the symbol table so the assembly reads like `call mkvparser::Block::Parse()` even for non-PLT calls.

## 3. Intel syntax flag

Add `--intel` to the `disasm` subcommand, passing `-M intel` to `objdump`. Intel syntax (`mov rax, [rdi+8]`) is more readable than AT&T (`mov 0x8(%rdi),%rax`) for most RE workflows. Regenerates assembly blocks in the method markdowns in Intel format.

## 4. Frida companion script

Auto-generate a Frida hook script from `disasm.json` that intercepts every exported function, logs arguments and return values, and writes them to a file. Cross-referencing the runtime log against elfinfo's static return type inference surfaces functions where the inference was wrong and gives ground truth for argument shapes.
