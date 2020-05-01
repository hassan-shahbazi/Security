import XCTest
@testable import Security

final class SecurityTests: XCTestCase {
    func testExample() {
        // This is an example of a functional test case.
        // Use XCTAssert and related functions to verify your tests produce the correct
        // results.
        XCTAssertEqual(Security().text, "Hello, World!")
    }

    static var allTests = [
        ("testExample", testExample),
    ]
}
