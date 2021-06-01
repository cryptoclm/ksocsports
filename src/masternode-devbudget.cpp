// Copyright (c) 2018-2019 The ZCore developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <masternode-devbudget.h>
#include <boost/filesystem.hpp>
#include <boost/lexical_cast.hpp>
#include <boost/foreach.hpp>

CDevBudget devbudget;

void CDevBudget::PrepareBudget() {
    CBitcoinAddress address = CBitcoinAddress(Params().GetConsensus().strDevFeeAddress);
    payee = GetScriptForDestination(address.Get());
    CBitcoinAddress address1 = CBitcoinAddress(Params().GetConsensus().strDevFeeAddress1);
    payee1 = GetScriptForDestination(address1.Get());

    LogPrintf("CDevBudget::PrepareBudget(): %s\n", address.ToString());
    LogPrintf("CDevBudget::PrepareBudget(): %s\n", address1.ToString());
}

bool CDevBudget::IsTransactionValid(const CTransaction& txNew, int nBlockHeight)
{
    CBlockIndex* pindexPrev = chainActive.Tip();
    if (!pindexPrev){
        return false;
    }

    for (const CTxIn& txin : txNew.vin) {
        if (!txin.IsZerocoinSpend()) {
		return true;
        }
    }

    CAmount budgetPayment = GetDevelopersPayment(nBlockHeight);

    bool found = false;
    int i = 0;
    if(budgetPayment > 0){
        BOOST_FOREACH (CTxOut out, txNew.vout) {
            if (payee == out.scriptPubKey) {
                if (i > 0 && out.nValue >= budgetPayment) {
                    found = true;
                }
                else{
                    LogPrintf("CDevBudget::IsTransactionValid - Found valid Dev Budget address, but wrong amount %d\n", out.nValue);
                }
            }
            i++;
        }
    }
    else{
        LogPrintf("CDevBudget::IsTransactionValid - Skipping validate devbudget, because is 0\n");
        found = true;
    }

    if (!found) {
        LogPrintf("CDevBudget::IsTransactionValid - Missing required payment %d for block %d\n", budgetPayment, nBlockHeight);
    }

    return found;
}

void CDevBudget::FillBlockPayee(CMutableTransaction& txNew, int64_t nFees, bool fProofOfStake)
{
    LogPrintf("Entered in CDevBudget::FillBlockPayee\n");

    CBlockIndex* pindexPrev = chainActive.Tip();
    if (!pindexPrev){
        return;
    }

    PrepareBudget();

    unsigned int i = txNew.vout.size();

    if(fProofOfStake && i > 1 && txNew.vout[1].IsZerocoinMint()){
        return;
    }

    if (txNew.vout[i - 1].nValue > 0) {
        CAmount budgetPayment = GetDevelopersPayment(pindexPrev->nHeight);
	CAmount DevFeePayment = budgetPayment / 2;
        if(budgetPayment > 0) {
            txNew.vout.resize(i + 2);
            txNew.vout[i].scriptPubKey = payee;
            txNew.vout[i].nValue = DevFeePayment;
            txNew.vout[i+1].scriptPubKey = payee1;
            txNew.vout[i+1].nValue = DevFeePayment;
            //subtract budget payment from mn reward
            txNew.vout[i - 2].nValue -= budgetPayment;

            //LogPrintf("Dev budget - Vout0 %s , Vout1 %s\n", FormatMoney(txNew.vout[i].nValue).c_str(), FormatMoney(txNew.vout[i+1].nValue).c_str());
            LogPrintf("Dev budget payment of %s to %s\n", FormatMoney(DevFeePayment).c_str(), Params().GetConsensus().strDevFeeAddress.c_str());
            LogPrintf("Dev budget payment of %s to %s\n", FormatMoney(DevFeePayment).c_str(), Params().GetConsensus().strDevFeeAddress1.c_str());
        }
        else{
            LogPrintf("Dev budget payment equals 0\n");
        }
    }
    else{
        LogPrintf("Can't insert dev budget payment: vout value equals 0\n");
    }
}
