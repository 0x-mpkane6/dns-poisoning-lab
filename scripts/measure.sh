#!/bin/bash

TOTAL=$(wc -l < ../client/result.txt)
POISON=$(grep "6.6.6.6" ../client/result.txt | wc -l)

echo "Total: $TOTAL"
echo "Poisoned: $POISON"

echo "Success rate = $(echo "$POISON * 100 / $TOTAL" | bc)%"
