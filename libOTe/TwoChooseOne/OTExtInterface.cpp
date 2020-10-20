#include "OTExtInterface.h"
#include "libOTe/Base/BaseOT.h"
#include <cryptoTools/Common/BitVector.h>
#include <vector>
#include <cryptoTools/Network/Channel.h>
#include <cryptoTools/Crypto/AES.h>

void osuCrypto::OtExtReceiver::genBaseOts(PRNG & prng, Channel & chl)
{

#ifdef LIBOTE_HAS_BASE_OT
    DefaultBaseOT base;
    auto count = baseOtCount();
    std::vector<std::array<block, 2>> msgs(count);
    base.send(msgs, prng, chl);

    setBaseOts(msgs, prng, chl);
#else
    throw std::runtime_error("The libOTe library does not have base OTs. Enable them to call this. " LOCATION);
#endif
}

void osuCrypto::OtExtSender::genBaseOts(PRNG & prng, Channel & chl)
{
#ifdef LIBOTE_HAS_BASE_OT
    DefaultBaseOT base;
    auto count = baseOtCount();
    std::vector<block> msgs(count);
    BitVector bv(count);
    bv.randomize(prng);

    base.receive(bv, msgs, prng, chl);
    setBaseOts(msgs, bv, chl);
#else
    throw std::runtime_error("The libOTe library does not have base OTs. Enable them to call this. " LOCATION);
#endif

}

void osuCrypto::OtReceiver::receiveChosen(
    const BitVector & choices, 
    span<block> recvMessages,
    PRNG & prng, 
    Channel & chl)
{
    receive(choices, recvMessages, prng, chl);
    std::vector<std::array<block,2>> temp(recvMessages.size());
    chl.recv(temp.data(), temp.size());
    auto iter = choices.begin();
    for (u64 i = 0; i < temp.size(); ++i)
    {
        recvMessages[i] = recvMessages[i] ^ temp[i][*iter];
        ++iter;
    }
}

void osuCrypto::OtSender::sendChosen(
    span<std::array<block, 2>> messages, 
    PRNG & prng, 
    Channel & chl)
{
    std::vector<std::array<block, 2>> temp(messages.size());
    send(temp, prng, chl);

    for (u64 i = 0; i < static_cast<u64>(messages.size()); ++i)
    {
        temp[i][0] = temp[i][0] ^ messages[i][0];
        temp[i][1] = temp[i][1] ^ messages[i][1];
    }

    chl.asyncSend(std::move(temp));
}

//-----------------------------------------------------------------

void osuCrypto::OtReceiver::receiveChosen(
    const BitVector & choices, 
    std::vector<std::vector<block>>& recvMessages,
    PRNG & prng, 
    Channel & chl)
{
    std::vector<block> recvKeys(choices.size());
    receive(choices, recvKeys, prng, chl);

    std::vector<AES> H(choices.size());
    for (u64 i = 0; i < choices.size(); ++i){
        H[i].setKey(recvKeys[i]);
    }

    for (u64 j = 0; j < recvMessages.size(); ++j){
        std::vector<std::array<block,2>> temp(choices.size());
        chl.recv(temp.data(), temp.size());
        auto iter = choices.begin();
        for (u64 i = 0; i < choices.size(); ++i){
            recvMessages[j][i] = H[i].ecbEncBlock(_mm_set_epi64x(0, j)) ^ temp[i][*iter];
            ++iter;
        }
    }
}

void osuCrypto::OtSender::sendChosen(
    std::vector<std::vector<std::array<block,2>>> messages, 
    PRNG & prng, 
    Channel & chl)
{
    std::vector<std::array<block,2>> sendKeys(messages[0].size());
    send(sendKeys, prng, chl);

    std::vector<std::array<AES,2>> H(messages[0].size());
    for (u64 i = 0; i < static_cast<u64>(messages[0].size()); ++i){
        H[i][0].setKey(sendKeys[i][0]);
        H[i][1].setKey(sendKeys[i][1]);
    }

    for (u64 j = 0; j < messages.size(); ++j){
        std::vector<std::array<block,2>> temp(messages[0].size());
        for (u64 i = 0; i < static_cast<u64>(messages[0].size()); ++i){
            temp[i][0] = H[i][0].ecbEncBlock(_mm_set_epi64x(0, j)) ^ messages[j][i][0];
            temp[i][1] = H[i][1].ecbEncBlock(_mm_set_epi64x(0, j)) ^ messages[j][i][1];
        }
        chl.asyncSend(std::move(temp));
    }
}