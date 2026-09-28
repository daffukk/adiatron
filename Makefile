.PHONY: all clean

all:
	mkdir -p build && \
	cd build && \
	cmake .. && \
	$(MAKE)
	@echo "==> Build completed successfully."

clean:
	@rm -rf build 
	@echo "Cleaning..."
