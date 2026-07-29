# 签名黄金向量生成器

两份独立实现，输出必须逐字节一致，用于校验 `src/sign.rs`。

    python3 gen_vectors.py
    GOFLAGS=-mod=mod go run .

两者的 `golden_1fe` / `golden_21e` 应与 `src/sign.rs` 单测里的黄金向量完全相同。
