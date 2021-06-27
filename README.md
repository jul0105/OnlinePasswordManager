<div align="center">
<h1>SEC Project: Password manager</h1>
<p>Made with :heart: by Gil Balsiger and Julien Béguin</p>
<a href="https://gitlab.com/jul0105/SEC_Projet/-/commits/main">
<img alt="pipeline status" src="https://gitlab.com/jul0105/SEC_Projet/badges/main/pipeline.svg?key_text=Tests" />
</a>
<img alt="pipeline status" src="https://img.shields.io/static/v1?logo=rust&label=Made%20in&message=Rust&color=blue" />
</div>
## Package documentation

This crate has an online documentation available [here](https://jul0105.gitlab.io/SEC_Projet/sec_project/index.html).

You can also generate the documentation locally with the following command :

```
cargo doc --no-deps --open
```



## Specification

See `SPECIFICATIONS.md` (please open the PDF file if you don't use Typora)



## Implementation

We have not implemented access control because it didn't made much sense on our system but we have implemented registration of users.

Other cool things we implemented (Bonus ? :))

- User use 2FA authenticator to generate a Time-based One Time Password (TOTP).
- Trying to mitigate timing attack by making (sort of) time-constant server endpoint
- Using Diesel for DB management
