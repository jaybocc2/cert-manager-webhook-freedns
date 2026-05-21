IMAGE_NAME := penguinade/cert-manager-webhook-freedns
IMAGE_TAG := dev

BUILDX_BUILDER := container-builder

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

build: ensure-buildx
	docker buildx build \
		--platform linux/amd64,linux/arm64 \
		-f Dockerfile \
		-t $(IMAGE_NAME):$(IMAGE_TAG) .

push: ensure-buildx
	docker buildx build \
		--platform linux/amd64,linux/arm64 \
		-f Dockerfile \
		-t $(IMAGE_NAME):$(IMAGE_TAG) \
		--push .

.PHONY: push
