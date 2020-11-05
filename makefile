.DEFAULT_GOAL := build
compiler = g++
cppver = c++17
buildpath = binaries



build: main
	@${compiler} binaries/*.o -o packetsniffer
	@echo "Linked Binaries"

main: pcapmaker helpers pktproc main.cpp
	@${compiler} -c -std=${cppver} $@.cpp -o ${buildpath}/$@.o
	@echo "Built main"


pcapmaker: pcapmaker.cpp
	@${compiler} -c -std=${cppver} $@.cpp -o ${buildpath}/$@.o
	@echo "Built pcapmaker"

helpers: helpers.cpp
	@${compiler} -c -std=${cppver} $@.cpp -o ${buildpath}/$@.o
	@echo "Built helpers"

pktproc: pktproc.cpp
	@${compiler} -c -std=${cppver} $@.cpp -o ${buildpath}/$@.o
	@echo "Built pktproc"

clean:
	rm binaries/*