.PHONY: build test run clean

build:
	docker build -t policyengine-github-bot .

test: build
	@echo "Starting container..."
	@CONTAINER_ID=$$(docker run -d -p 8080:8080 --env-file .env policyengine-github-bot); \
	echo "Container ID: $$CONTAINER_ID"; \
	echo "Waiting for container to start..."; \
	sleep 3; \
	if curl -sf http://localhost:8080/health > /dev/null; then \
		echo "✓ Health check passed"; \
		docker stop $$CONTAINER_ID > /dev/null; \
		docker rm $$CONTAINER_ID > /dev/null; \
		exit 0; \
	else \
		echo "✗ Health check failed"; \
		echo "Container logs:"; \
		docker logs $$CONTAINER_ID; \
		docker stop $$CONTAINER_ID > /dev/null; \
		docker rm $$CONTAINER_ID > /dev/null; \
		exit 1; \
	fi

run: build
	docker run -p 8080:8080 --env-file .env policyengine-github-bot

clean:
	docker rmi policyengine-github-bot 2>/dev/null || true
