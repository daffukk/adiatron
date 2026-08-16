.PHONY: all clean

all:
	mkdir -p build && \
	cd build && \
	cmake .. && \
	$(MAKE) && \
	mv -f adiatron ..
	@echo "==> Build completed successfully."

clean:
	@rm -rf build adiatron
	@echo "Cleaning..."
