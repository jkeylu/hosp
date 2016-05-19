version:=$(shell sed -n "s/.*VERSION = \"\(.*\)\".*/\1/p" main.go)

compile:
	go build -o dist/hosp

archive:
	pushd dist && tar zcvf hosp-v$(version)-$(shell uname -s)-$(shell uname -m).tar.gz hosp && popd

.PHONY: clean
clean:
	rm -rf dist/

all: clean compile

pack: clean compile archive
