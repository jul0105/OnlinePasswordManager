# Online password manager

This project is part of my [bachelor thesis](https://github.com/jul0105/Bachelor-Thesis/raw/master/report.pdf). The main goal of this proof of concept is to demonstrates the usefulness of [KHAPE](https://github.com/jul0105/KHAPE) for such applications. This prototype is based on an existing online password manager project that was developed earlier this year by Gil Balsiger and me. 



## Usage

Simply run the application with `cargo run` and the CLI client will walk your through the password manager.



## Documentation

Documentation is available by executing the following command :

```
cargo doc --no-deps --open
```



## Implementation

- Use KHAPE for authentication
- Use of 2FA
- CLI client
- Server uses SQLite database
- Client-server setting but currently the network between the two parties is simulated

For details on the design and the implementation of this use case, refer to the chapter 5 of my [bachelor thesis](https://github.com/jul0105/Bachelor-Thesis/raw/master/report.pdf).