package main

import (
	"fmt"
	"testing"
)

func TestParsePacket(t *testing.T) {
	line := `11:13:09.115134 IP (tos 0xa,ECT(0), ttl 62, id 28639, offset 0, flags [DF], proto TCP (6), length 96)
    122.228.207.19.22 > 153.35.127.167.25040: Flags [P.], cksum 0x6315 (incorrect -> 0xed8d), seq 98621:98665, ack 11548, win 1281, options [nop,nop,TS val 1434557501 ecr 3302201581], length 44`

	parsePacket(line, false)

	fmt.Println(*throughput)
	fmt.Println(*packets.MetricVec)
}