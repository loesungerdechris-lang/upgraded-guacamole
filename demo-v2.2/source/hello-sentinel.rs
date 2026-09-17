fn greeting() -> &'static str {
    "Hello, SENTINEL."
}

fn main() {
    println!("{}", greeting());
}

#[cfg(test)]
mod tests {
    use super::greeting;

    #[test]
    fn reports_the_expected_demo_identity() {
        assert_eq!(greeting(), "Hello, SENTINEL.");
    }
}
