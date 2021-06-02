fn main() {
    println!("Hello, world!");
}

#[cfg(test)]
mod tests {

    #[test]
    fn test_ok() {
        assert_eq!(4, 2 + 2);
    }

}