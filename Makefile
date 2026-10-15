.PHONY: all debug clean

PROJECT_DIR := $(realpath .)
BUILD_DIR := $(PROJECT_DIR)/build

all:
	@mkdir -p "$(BUILD_DIR)"
	cmake -S "$(PROJECT_DIR)" -B "$(BUILD_DIR)"
	cmake --build "$(BUILD_DIR)" --parallel
	@echo "==> Build completed successfully."

debug:
	@mkdir -p "$(BUILD_DIR)"
	cmake -DCMAKE_BUILD_TYPE=Debug -S "$(PROJECT_DIR)" -B "$(BUILD_DIR)"
	cmake --build "$(BUILD_DIR)" --parallel
	@echo "==> Build completed successfully. DEBUG BUILD!"

clean:
	@rm -rf "$(BUILD_DIR)" 
	@echo "Cleaning..."
