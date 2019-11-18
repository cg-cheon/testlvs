V=0.1

all:	testlvs

testlvs:	testlvs.c
	gcc -Wall -g -o testlvs testlvs.c

clean:
	rm -f core *.o testlvs *~

tar:	clean
	cd .. && tar cfz testlvs-$V.tar.gz testlvs-$V
