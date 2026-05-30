IMAGE_NAME ?= acme/java25-demo:latest

.PHONY: build test certify scan

build:
	docker build -t $(IMAGE_NAME) .

test:
	./tests/smoke.sh $(IMAGE_NAME)

certify:
	docker save $(IMAGE_NAME) -o image.tar
	clearcutt certify image.tar \
	  --policy policy.yaml \
	  --base java25-distroless
	rm -f image.tar

scan:
	grype $(IMAGE_NAME)
