VERSION = v0.1

build:
	echo "Building the CLI application..."
	go build -ldflags "-X 'internal/version.Version=$(VERSION)'" -o shush
