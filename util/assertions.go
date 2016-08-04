package util

func AssertSuccess(err error) {
	if err != nil {
		panic(err)
	}
}

