#!/bin/bash

# Simple sciprt to act as regression testing
# Tests are
# 1. Hande written
# 2. LLVM unit test (from it's test-suite)
# 3. Real world regression_applications

# Simple coloring scheme to help the user see what's going on
RED='\033[0;31m'
NC='\033[0m' # NC = No Color
GREEN='\033[0;32m'

TEST_FAILED=0

# Run test function
# Input: Test to run (path with respect to the script dir)
# Output: none
# Exception: exits with the test that failed to notify the user
function run_test {
	b=$(basename $1)
	c="${1%.*}.reference_output"
	d="$2/$b"
	make clean &> /dev/null
	make NO_COUNTERS="-DNO_COUNTERS" UnitTest_File=$d &> /dev/null
	echo "processing test file $b"
	./test > test_temp_file
	echo "exit $?" >> test_temp_file
	DIFF=$(diff test_temp_file $c)
	if [ "$DIFF" != "" ]
	then
		echo -e "${RED}[ERROR] TEST Failed $d ${NC}"
		TEST_FAILED=$((TEST_FAILED+1))
		#exit
	fi
}

# make host regression_app - used for all enclaves tested
#make -C ../ -f Makefile;

# clean state
#make -C ../../pass -f Makefile clean &> /dev/null;
#make -C ../../pass -f Makefile SDK_BUILD="" NO_COUNTERS="-DNO_COUNTERS" &> /dev/null
#make -C ../../runtime -f Makefile clean &> /dev/null;
#make -C ../../runtime -f Makefile SDK_BUILD="" NO_COUNTERS="-DNO_COUNTERS" &> /dev/null;

make clean &> /dev/null;
rm -f test_temp_file

# User friendly message
echo -e "${GREEN}[Processing Unit Tests]${NC}"

DRY_TESTS=./Misc/*.c

for t in $DRY_TESTS
do
	run_test $t Misc
done

rm -f test_temp_file

# Test start here:
UNIT_TESTS=./unit_tests/*.c

for t in $UNIT_TESTS
do
	run_test $t unit_tests
done

rm -f test_temp_file

# Next make specific test cases with enclaves
SIGNLESS_TESTS=./SignlessTypes/*.c
for t in $SIGNLESS_TESTS
do
	run_test $t SignlessTypes
done

rm -f test_temp_file

echo -e "${GREEN}[Processing LLVM Single Source Tests]${NC}"

TLS_TESTS=./Threads/*.c
for t in $TLS_TESTS
do
	run_test $t Threads
done

rm -f test_temp_file


SINGLE_SOURCE_TESTS=./single_source_tests/*.c

for t in $SINGLE_SOURCE_TESTS
do
	run_test $t single_source_tests
done

rm -f test_temp_file

echo -e "${GREEN}[Processing full regression_applications enclaves Tests]${NC}"

# Linear algebra computations enclave
LINPACK_TESTS=./Linpack/*.c

for t in $LINPACK_TESTS
do
	run_test $t Linpack
done

rm -f test_temp_file

REGRESSION_TESTS=./regression/*.c

for t in $REGRESSION_TESTS
do
	run_test $t regression
done

rm -f test_temp_file

# Lastly, tests end - return success message to user

if [ "$TEST_FAILED" != 0 ]
then
	echo -e "${RED}[FAIL] SOME TESTS FAILED${NC}"
else
	echo -e "${GREEN}[SUCCESS] ALL TEST PASSED${NC}"
fi
