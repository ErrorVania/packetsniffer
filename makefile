.DEFAULT_GOAL := main
compiler = g++
cppver = c++17
buildpath = binaries





main: pcapmaker helpers pktproc main.cpp
	@${compiler} -c -std=${cppver} main.cpp -o ${buildpath}/main.o
	@echo "Built main"


pcapmaker: pcapmaker.cpp
	@${compiler} -c -std=${cppver} pcapmaker/pcapmaker.cpp -o ${buildpath}/pcapmaker.o
	@echo "Built pcapmaker"

helpers: helpers.cpp
	@${compiler} -c -std=${cppver} helpers/helpers.cpp -o ${buildpath}/helpers.o
	@echo "Built helpers"

pktproc: pktproc.cpp
	@${compiler} -c -std=${cppver} pktproc/pktproc.cpp -o ${buildpath}/pktproc.o
	@echo "Built pktproc"

clean:
	rm binaries/*.o