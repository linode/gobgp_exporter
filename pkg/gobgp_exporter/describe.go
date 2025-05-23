// Copyright 2018 Paul Greenberg (greenpau@outlook.com)
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package exporter

import (
	"github.com/prometheus/client_golang/prometheus"
)

// Describe describes all the metrics ever exported by the exporter. It
// implements prometheus.Collector.
func (n *RouterNode) Describe(ch chan<- *prometheus.Desc) {
	ch <- routerUp
	ch <- routerID
	ch <- routerHostname
	ch <- routerLocalAS
	ch <- routerErrors
	ch <- routerNextScrape
	ch <- routerScrapeTime
	ch <- routerRibTotalDestinationCount
	ch <- routerRibTotalPathCount
	ch <- routerRibAcceptedPathCount
	ch <- routerPeers
	ch <- routerPeer
	ch <- routerPeerAsn
	ch <- routerPeerLocalAsn
	ch <- routerPeerAdminState
	ch <- routerPeerSessionState
	ch <- bgpPeerReceivedTotalMessagesCount
	ch <- bgpPeerReceivedNotificationMessagesCount
	ch <- bgpPeerReceivedUpdateMessagesCount
	ch <- bgpPeerReceivedOpenMessagesCount
	ch <- bgpPeerReceivedKeepaliveMessagesCount
	ch <- bgpPeerReceivedRefreshMessagesCount
	ch <- bgpPeerReceivedWithdrawUpdateMessagesCount
	ch <- bgpPeerReceivedWithdrawPrefixMessagesCount
	ch <- bgpPeerSentTotalMessagesCount
	ch <- bgpPeerSentNotificationMessagesCount
	ch <- bgpPeerSentUpdateMessagesCount
	ch <- bgpPeerSentOpenMessagesCount
	ch <- bgpPeerSentKeepaliveMessagesCount
	ch <- bgpPeerSentRefreshMessagesCount
	ch <- bgpPeerSentWithdrawUpdateMessagesCount
	ch <- bgpPeerSentWithdrawPrefixMessagesCount
	ch <- bgpPeerOutQueue
	ch <- bgpPeerFlops
	ch <- bgpPeerSendCommunityFlag
	ch <- bgpPeerRemovePrivateAsFlag
	ch <- bgpPeerPasswodSetFlag
	ch <- bgpPeerType
	ch <- bgpPeerAfiSafiStateAccepted
	ch <- bgpPeerAfiSafiStateAdvertised
	ch <- bgpPeerAfiSafiStateReceived
}
