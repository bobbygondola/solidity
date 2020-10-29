library L{
	function f() internal {
		new C();
	}
}

contract D {
	function f() public {
		L.f();
	}
}
contract C {
	constructor() { new D(); }
}

// ----
// TypeError 7813: (91-94): Circular reference found.
// TypeError 7813: (133-138): Circular reference found.
// TypeError 7813: (38-43): Circular reference found.
