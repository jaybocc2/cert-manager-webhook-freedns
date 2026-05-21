include build.env
-include build.env.work
export

IMAGE_NAME ?= webhook
IMAGE_TAG  ?= dev

BUILDX_BUILDER ?= container-builder
BUILDINFO_FILE := freedns/buildinfo_gen.go

ensure-buildx:
	@if ! docker buildx inspect $(BUILDX_BUILDER) >/dev/null 2>&1; then \
		echo "Creating buildx builder $(BUILDX_BUILDER)..."; \
		docker buildx create \
			--name $(BUILDX_BUILDER) \
			--driver docker-container \
			--driver-opt network=host \
			--bootstrap --use; \
	else \
		echo "Using existing buildx builder $(BUILDX_BUILDER)"; \
		docker buildx use $(BUILDX_BUILDER); \
	fi

.buildinfo:
	@mkdir -p $(dir $(BUILDINFO_FILE))
	@printf '%s\n' \
		'package freedns' \
		'' \
		'const (' \
		'	IMAGE_TAG   = "$(IMAGE_TAG)"' \
		'	Timestamp   = "'$$(TZ=UTC date +%Y%m%d.%H%M%S)'"' \
		')' \
	> $(BUILDINFO_FILE)

build: .buildinfo ensure-buildx
	docker buildx build \
		--platform linux/amd64,linux/arm64 \
		-f Dockerfile \
		-t $(IMAGE_NAME):$(IMAGE_TAG) .

push: .buildinfo ensure-buildx
	docker buildx build \
		--platform linux/amd64,linux/arm64 \
		-f Dockerfile \
		-t $(IMAGE_NAME):$(IMAGE_TAG) \
		--push .

inspect:
	docker buildx imagetools inspect $(IMAGE_NAME):$(IMAGE_TAG)

.PHONY: push build .buildinfo
