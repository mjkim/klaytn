package api

import (
	"context"
	"encoding/json"
	"math/big"
	"reflect"
	"testing"

	"github.com/golang/mock/gomock"

	mock_api "github.com/klaytn/klaytn/api/mocks"
	"github.com/klaytn/klaytn/blockchain/types"
	"github.com/klaytn/klaytn/common"
	"github.com/klaytn/klaytn/common/hexutil"
	"github.com/klaytn/klaytn/consensus/mocks"
	"github.com/klaytn/klaytn/crypto"
	"github.com/klaytn/klaytn/networks/rpc"
	"github.com/klaytn/klaytn/params"
	"github.com/klaytn/klaytn/rlp"
	"github.com/stretchr/testify/assert"
)

// TestEthereumAPI_GetHeaderByNumber tests GetHeaderByNumber.
func TestEthereumAPI_GetHeaderByNumber(t *testing.T) {
	testGetHeader(t, "GetHeaderByNumber")
}

// TestEthereumAPI_GetHeaderByHash tests GetHeaderByNumber.
func TestEthereumAPI_GetHeaderByHash(t *testing.T) {
	testGetHeader(t, "GetHeaderByHash")
}

// testGetHeader generates data to test GetHeader related functions in EthereumAPI
// and actually tests the API function passed as a parameter.
func testGetHeader(t *testing.T, testAPIName string) {
	mockCtrl := gomock.NewController(t)
	mockBackend := mock_api.NewMockBackend(mockCtrl)

	api := EthereumAPI{
		publicKlayAPI:       NewPublicKlayAPI(mockBackend),
		publicBlockChainAPI: NewPublicBlockChainAPI(mockBackend),
	}

	// Creates a MockEngine.
	mockEngine := mocks.NewMockEngine(mockCtrl)
	// GetHeader APIs calls internally below methods.
	mockBackend.EXPECT().Engine().Return(mockEngine)
	// Author is called when calculates miner field of Header.
	dummyMiner := common.HexToAddress("0x9712f943b296758aaae79944ec975884188d3a96")
	mockEngine.EXPECT().Author(gomock.Any()).Return(dummyMiner, nil)
	var dummyTotalDifficulty uint64 = 5
	mockBackend.EXPECT().GetTd(gomock.Any()).Return(new(big.Int).SetUint64(dummyTotalDifficulty))

	// Create dummy header
	header := types.CopyHeader(&types.Header{
		ParentHash:  common.HexToHash("0xc8036293065bacdfce87debec0094a71dbbe40345b078d21dcc47adb4513f348"),
		Rewardbase:  common.Address{},
		Root:        common.HexToHash("0xad31c32942fa033166e4ef588ab973dbe26657c594de4ba98192108becf0fec9"),
		ReceiptHash: common.HexToHash("0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"),
		Bloom:       types.Bloom{},
		BlockScore:  new(big.Int).SetUint64(1),
		Number:      new(big.Int).SetUint64(4),
		GasUsed:     uint64(10000),
		Time:        new(big.Int).SetUint64(1641363540),
		TimeFoS:     uint8(85),
		Extra:       common.Hex2Bytes("0xd983010701846b6c617988676f312e31362e338664617277696e000000000000f89ed5949712f943b296758aaae79944ec975884188d3a96b8415a0614be7fd5ea40f11ce558e02993bd55f11ae72a3cfbc861875a57483ec5ec3adda3e5845fd7ab271d670c755480f9ef5b8dd731f4e1f032fff5d165b763ac01f843b8418867d3733167a0c737fa5b62dcc59ec3b0af5748bcc894e7990a0b5a642da4546713c9127b3358cdfe7894df1ca1db5a97560599986d7f1399003cd63660b98200"),
		Governance:  []byte{},
		Vote:        []byte{},
	})

	var blockParam interface{}
	switch testAPIName {
	case "GetHeaderByNumber":
		blockParam = rpc.BlockNumber(header.Number.Uint64())
		mockBackend.EXPECT().HeaderByNumber(gomock.Any(), gomock.Any()).Return(header, nil)
	case "GetHeaderByHash":
		blockParam = header.Hash()
		mockBackend.EXPECT().HeaderByHash(gomock.Any(), gomock.Any()).Return(header, nil)
	}

	results := reflect.ValueOf(&api).MethodByName(testAPIName).Call(
		[]reflect.Value{
			reflect.ValueOf(context.Background()),
			reflect.ValueOf(blockParam),
		},
	)
	ethHeader, ok := results[0].Interface().(map[string]interface{})
	assert.Equal(t, true, ok)
	assert.NotEqual(t, ethHeader, nil)

	expected := make(map[string]interface{})
	assert.NoError(t, json.Unmarshal([]byte(`
	{
	  "jsonrpc": "2.0",
	  "id": 1,
	  "result": {
		"baseFeePerGas": "0x0",
		"difficulty": "0x1",
		"extraData": "0x",
		"gasLimit": "0x3b9ac9ff",
		"gasUsed": "0x2710",
		"hash": "0x55dc3fb675db73376149a9c03c04ece912360a87f9d4e0138212eb8a0400df08",
		"logsBloom": "0x00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
		"miner": "0x9712f943b296758aaae79944ec975884188d3a96",
		"mixHash": "0x0000000000000000000000000000000000000000000000000000000000000000",
		"nonce": "0x0000000000000000",
		"number": "0x4",
		"parentHash": "0xc8036293065bacdfce87debec0094a71dbbe40345b078d21dcc47adb4513f348",
		"receiptsRoot": "0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470",
		"sha3Uncles": "0x1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347",
		"size": "0x20c",
		"stateRoot": "0xad31c32942fa033166e4ef588ab973dbe26657c594de4ba98192108becf0fec9",
		"timestamp": "0x61d53854",
		"totalDifficulty": "0x5",
		"transactionsRoot": "0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"
	  }
	}
    `), &expected))
	checkEthereumBlockOrHeaderFormat(t, expected, ethHeader)
}

// checkEthereumHeaderFormat checks that ethBlockOrHeader returned from
// GetHeader or GetBlock APIs have all keys of the Ethereum data structure and
// also checks the immutable values are well-defined or not.
func checkEthereumBlockOrHeaderFormat(
	t *testing.T,
	expected map[string]interface{},
	ethBlockOrHeader map[string]interface{},
) {
	expectedResult, ok := expected["result"].(map[string]interface{})
	assert.True(t, ok)

	// Check immutable values.
	nonce := ethBlockOrHeader["nonce"]
	assert.Equal(t, BlockNonce{}, nonce)

	mixHash := ethBlockOrHeader["mixHash"]
	assert.Equal(t, common.Hash{}, mixHash)

	emptyUncleHeaders, err := rlp.EncodeToBytes([]*types.Header(nil))
	assert.NoError(t, err)
	emptySha3Uncles := crypto.Keccak256Hash(emptyUncleHeaders)
	sha3Uncles := ethBlockOrHeader["sha3Uncles"]
	assert.Equal(t, common.HexToHash(EmptySha3Uncles), sha3Uncles)
	assert.Equal(t, emptySha3Uncles, sha3Uncles)

	extraData := ethBlockOrHeader["extraData"]
	assert.Equal(t, hexutil.Bytes{}, extraData)

	gasLimit := ethBlockOrHeader["gasLimit"]
	assert.Equal(t, hexutil.Uint64(DummyGasLimit), gasLimit)

	baseFeePerGas := ethBlockOrHeader["baseFeePerGas"]
	assert.Equal(t, (*hexutil.Big)(new(big.Int).SetUint64(params.BaseFee)), baseFeePerGas)

	// Check other values
	// make sure that rpcMarshalHeader assigns fields values properly.
	expectedGasUsed, _ := new(big.Int).SetString(expectedResult["gasUsed"].(string)[2:], 16)
	assert.Equal(t, hexutil.Uint64(expectedGasUsed.Uint64()), ethBlockOrHeader["gasUsed"])
	expectedBloom := types.Bloom{}
	expectedBloom.SetBytes(common.Hex2Bytes(expectedResult["logsBloom"].(string)))
	assert.Equal(t, expectedBloom, ethBlockOrHeader["logsBloom"].(types.Bloom))
	assert.Equal(t, common.HexToAddress(expectedResult["miner"].(string)), ethBlockOrHeader["miner"].(common.Address))
	expectedNumber, _ := new(big.Int).SetString(expectedResult["number"].(string)[2:], 16)
	assert.Equal(t, expectedNumber.Uint64(), ethBlockOrHeader["number"].(*hexutil.Big).ToInt().Uint64())
	assert.Equal(t, common.HexToHash(expectedResult["hash"].(string)), ethBlockOrHeader["hash"].(common.Hash))
	assert.Equal(t, common.HexToHash(expectedResult["parentHash"].(string)), ethBlockOrHeader["parentHash"].(common.Hash))
	assert.Equal(t, common.HexToHash(expectedResult["receiptsRoot"].(string)), ethBlockOrHeader["receiptsRoot"].(common.Hash))
	assert.Equal(t, expectedResult["size"].(string), ethBlockOrHeader["size"].(hexutil.Uint64).String())
	assert.Equal(t, common.HexToHash(expectedResult["stateRoot"].(string)), ethBlockOrHeader["stateRoot"].(common.Hash))
	expectedTimestamp, _ := new(big.Int).SetString(expectedResult["timestamp"].(string)[2:], 16)
	actualTimeStamp, _ := ethBlockOrHeader["timestamp"].(hexutil.Big)
	assert.Equal(t, expectedTimestamp.Uint64(), actualTimeStamp.ToInt().Uint64())
	expectedTotalDifficulty, _ := new(big.Int).SetString(expectedResult["totalDifficulty"].(string)[2:], 16)
	assert.Equal(t, expectedTotalDifficulty.Uint64(), ethBlockOrHeader["totalDifficulty"].(*hexutil.Big).ToInt().Uint64())
	assert.Equal(t, common.HexToHash(expectedResult["transactionsRoot"].(string)), ethBlockOrHeader["receiptsRoot"].(common.Hash))
}
