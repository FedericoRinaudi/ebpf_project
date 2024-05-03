build:
	make -C src

clean:
	make -C src clean

install:
	apt-get -y install sudo
	sudo apt update
	sudo apt-get install -y --no-install-recommends \
        libelf1 libelf-dev zlib1g-dev \
        make clang llvm

run: install build
	sudo ./src/bootstrap eth0