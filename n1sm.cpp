#include "tmCmnTypes.h"
#include "tmNasMsgTypes.h"
#include <string.h>
#include <iostream>
#include <sstream>
#include <iomanip>
#include <bitset>	
#include <cryptopp/simple.h> 
#include <stdlib.h>
#include "cryptopp/hex.h"
#include <bits/stdc++.h> 
using namespace std;

U32  decodeN1SMData(U8  *pBuf, tmNasPduSession *pN1SmInfo) {
    std::cout << "----------------Decoding-----------------" << '\n';
	std::cout << pBuf <<'\n';
	string bufferstring = "";
	for (int i=0; pBuf[i]!='\0' ;i++)
	{
		bufferstring+=pBuf[i];
	}
	int bufferlength = bufferstring.size();

	//using hexdecoder to convert two octets to a single octet.                         
	string encoded=bufferstring;
	string decoded;
	
	//using hex decoder to convert 16bits to 1byte
	CryptoPP::HexDecoder decoder;
	decoder.Put( (CryptoPP::byte*)encoded.data(), encoded.size() );
	decoder.MessageEnd();
	CryptoPP::word64 size = decoder.MaxRetrievable();
	if(size && size <= SIZE_MAX)
	{
		decoded.resize(size);		
		decoder.Get((CryptoPP::byte*)&decoded[0], encoded.size());
	}
	
	//Manditory fields in all the messages 
	pN1SmInfo->extProtoDisc = decoded[0];	//Extended Protocol Discriminator
	pN1SmInfo->pduSessionId = decoded[1];	//PDU session Type
	pN1SmInfo->procTxnId = decoded[2];		//Protocol Transaction ID
	pN1SmInfo->msgType = decoded[3];		//Message type
	
	int index;
	U8 msgType = decoded[3];
	U8 pduSessionType, sscMode, octet;
	U16 length;
	//PDU Session Establishment cases

	//PDU session establishment request
	if (msgType == 0xc1) {
		std::cout << "<----PDU session establishment request----> \n";
		std::cout << "Intergrity Protection Max Data Rate\n";
		//Intergrity Protection Maximum Bit Rate
		pN1SmInfo->intgProtectionMBR[0] = 0x13;
		pN1SmInfo->intgProtectionMBR[1] = decoded[4];
		pN1SmInfo->intgProtectionMBR[2] = decoded[5];
		index=6;
	}

	//PDU session establishment accept
	else if( msgType == 0xc2) {
		std::cout << "PDU session establishment accept\n";
		octet = decoded[4];
		pduSessionType = decoded[4] >> 4 ;
		sscMode = octet << 5;
		sscMode = sscMode >> 5;
		pN1SmInfo->pduSessionType = pduSessionType;	//PDU Session Type
		pN1SmInfo->sscMode = sscMode;				// SSC Mode
		length = decoded[5] << 8;
		length = length | decoded[6];
		//QoS Rules
		pN1SmInfo->pQosRules = (tmNasTlvExtendTypeT*) malloc(sizeof
		(tmNasTlvExtendTypeT)+length);

		pN1SmInfo->pQosRules->tag = 0x7A;
		pN1SmInfo->pQosRules->length = length;
		for (int k = 0, j = 7 ; j <length+7 ;k++, j++) {
			pN1SmInfo->pQosRules->value[k] = decoded[j];
		}
		pN1SmInfo->sessionAMBR[0] = 0x2a;		// Session AMBR
		for(int k = 1, j = length+7; j < length+7+7 ; j++, k++) {
			pN1SmInfo->sessionAMBR[k] = decoded[j];
		}
		index = length+7+7;
		cout << index << '\n';
	}

	//PDU session establishment reject
	else if(msgType == 0xc3) {
		std::cout << "PDU session establishment reject \n";
		pN1SmInfo->gsmCause[0] = 0x59;			//5GSM cause
		pN1SmInfo->gsmCause[1] = decoded[4];
		index = 5;
	}
		

	//PDU Session Authentication cases
	//PDU session authentication command
	else if (msgType == 0xc5) {
		std::cout << "PDU session authentication command \n";
		length = decoded[4] << 8;
		length = length | decoded[5];
		pN1SmInfo->pEAPmsg = (tmNasTlvExtendTypeT*) 
		malloc(sizeof(tmNasTlvExtendTypeT)+length);	//QoS Rules

		pN1SmInfo->pEAPmsg->tag = 0x78;
		pN1SmInfo->pEAPmsg->length = length;
		for (int k = 0, j = 6 ; j < length+6 ;k++, j++) {
			pN1SmInfo->pEAPmsg->value[k] = decoded[j];
		}
		index = length + 6;
	}

	//PDU session authentication complete
	else if (msgType == 0xc6) {
		std::cout << "PDU session authentication complete \n";
		length = decoded[4] << 8;
		length = length | decoded[5];
		pN1SmInfo->pEAPmsg = (tmNasTlvExtendTypeT*)
		malloc(sizeof(tmNasTlvExtendTypeT)+length);	//QoS Rules

		pN1SmInfo->pEAPmsg->tag = 0x78;
		pN1SmInfo->pEAPmsg->length = length;
		for (int k = 0, j = 6 ; j < length+6 ;k++, j++) {
			pN1SmInfo->pEAPmsg->value[k] = decoded[j];
		}
		index = length + 6;
	}

	//PDU session authentication result 
	else if (msgType == 0xc7) {
		std::cout << "PDU session authentication result \n";
		// its does not have  manditory IEs than the common manditory IEs
		index = 4;
	}

	//PDU Session Modification cases

	//PDU session modification request
	else if(msgType == 0xc9) {
		std::cout << "PDU session modification request \n";
		// its does not have manditory IEs than the common manditory IEs
		index = 4;
	}

	//PDU session modification reject
	else if(msgType == 0xca) {
		std::cout << "PDU session modification reject \n";
		pN1SmInfo->gsmCause[0] = 0x59;			//5GSM cause
		pN1SmInfo->gsmCause[1] = decoded[4];
		index = 5;
	}

	//PDU session modification command
	else if(msgType == 0xcb) {
		std::cout << "PDU session modification command \n";
		// its does not have manditory IEs than the common manditory IEs
		index = 4;
	}

	//PDU session modification complete
	else if(msgType == 0xcc) {
		std::cout << "PDU session modification complete \n";
		// its does not have manditory IEs than the common manditory IEs
		index = 4;
	}

	//PDU session modification command reject
	else if(msgType == 0xcd) {
		std::cout << "PDU session modification command reject \n";
		pN1SmInfo->gsmCause[0] = 0x59;	//5GSM cause
		pN1SmInfo->gsmCause[1] = decoded[4];
		index = 5;
	}

	//PDU Session Release cases
	//PDU session release request
	else if(msgType == 0xd1) {
		std::cout << "PDU session release request \n";
		//its does not have manditory IEs than the common manditory IEs
		index = 4;
	}

	//PDU session release reject
	else if(msgType == 0xd2) {
		std::cout << "PDU session release reject \n";
		pN1SmInfo->gsmCause[0] = 0x59;		//5GSM cause
		pN1SmInfo->gsmCause[1] = decoded[4];
		index = 5;
	}

	//PDU session release command
	else if(msgType == 0xd3) {
		std::cout << "PDU session release command \n";
		pN1SmInfo->gsmCause[0] = 0x59;		//5GSM cause
		pN1SmInfo->gsmCause[1] = decoded[4];
		index = 5;
	}

	//PDU session release complete
	else if(msgType == 0xd4) {
		std::cout << "PDU session release complete \n";
		//it does not have manditory IEs than the common manditory IEs
		index = 4;
	}

	//PDU Session 5GSM status
	else if(msgType == 0xd6) {
		std::cout << "5GSM status \n";
		pN1SmInfo->gsmCause[0] = 0x59;	//5GSM cause
		pN1SmInfo->gsmCause[1] = decoded[4];
		index = 5;
	}

	else {
		cout << "invalid message type" <<endl;
	}

	//optional fields 
	while (index <bufferlength/2) {
		U8 temp = decoded[index];
		U8 temp1 = (temp << 4);
		U8 content = temp1 >>4;			// actual content
		U8 iei = temp >> 4;				// information element identifier
		U16 length;
		U8 octet2,octet3;
		U8 octet;
		
		// iei = Information Element Identifier
		
		//pN1SmInfo->alwaysOnPduSessionIndcation
		if (iei == 0x8) {
			std::cout << "Always-on PDU session indication\n";
			//assigning the always-on pdusession indication to the pN1SmInfo 
			//object
			pN1SmInfo->alwaysOnPduSessionIndcation = content;					
			pN1SmInfo->bitMask |= NAS_PDU_SESSION_ALWAYS_ON_PDU_SESSION_INDICATION;
			index++;
		}

		//pN1SmInfo->pduSessionType
		else if (iei == 0x9) {
			std::cout << "pduSession Type\n";
			//assigning value to pN1SmInfo object
			pN1SmInfo->pduSessionType= content;
			pN1SmInfo->bitMask |= NAS_PDU_SESSION_TYPE;
			index++;
		}

		//pN1SmInfo->sscMode	
		else if (iei == 0xa) {
			std::cout << "ssc_mode:\n";
			//assigning the mode value to the pN1SmInfo object
			pN1SmInfo->sscMode = content;										
			pN1SmInfo->bitMask |= NAS_PDU_SESSION_SSC_MODE;
			index++;
		}

		//pN1SmInfo->alwaysOnPduSessionReqt
		else if (iei == 0xb) {
			std::cout << "Always on PDU session Requested:\n";
			//assigning the mode value to the pN1SmInfo object
			pN1SmInfo->alwaysOnPduSessionReqt = content;					
			pN1SmInfo->bitMask |= NAS_PDU_SESSION_ALWAYS_ON_PDU_SESSION_REQ;
			index++;
		}

		//pN1SmInfo->allowedSscMode
		else if (iei == 0xf) {
			std::cout << "Allowed SSC Mode\n";
			pN1SmInfo->allowedSscMode = content;
			pN1SmInfo->bitMask |= NAS_PDU_SESSION_ALLOWED_SSC_MODE;
			index++;
		}

		else {
			// moving to TV type IEI's
			octet = decoded[index];//type value tags			
						
			//pN1SmInfo->intgProtectionMBR
			if (octet == 0x13) {
				std::cout << "Integrity protection maximum data rate \n";
				pN1SmInfo->intgProtectionMBR[0] = decoded[index];
				pN1SmInfo->intgProtectionMBR[1] = decoded[index+1];
				pN1SmInfo->intgProtectionMBR[2] = decoded[index+2];
				index += 3;
				pN1SmInfo->bitMask |= NAS_PDU_SESSION_INTEGRITY_PROTECTION_MAX_DATA_RATE;
			}
			
			//pN1SmInfo->pSNSSAI
			else if (octet == 0x22) {
				std::cout << "S-NSSAI\n";
				length = decoded[index+1];
				tmNasTlvTypeT *pSNSSAI = (tmNasTlvTypeT*) 
				malloc(sizeof(tmNasTlvTypeT)+length);			//Type 4

				pSNSSAI->tag = decoded[index];
				pSNSSAI->length = decoded[index+1];
				for (int k = 0, j = index+2 ; j < length+index+2 ;k++, j++) {
					pSNSSAI->value[k] = decoded[j];
				}
                pN1SmInfo->pSNSSAI = pSNSSAI;
				pN1SmInfo->bitMask |= NAS_PDU_SESSION_S_NSSAI;
				index += length+2;
			}

			//pN1SmInfo->pDNN
			else if (octet == 0x25) {
				std::cout << "DNN\n";
				length = decoded[index+1];
				tmNasTlvTypeT *pDNN = (tmNasTlvTypeT*) 
				malloc(sizeof(tmNasTlvTypeT)+length);			//Type 4

				pDNN->tag = decoded[index];
				pDNN->length = decoded[index+1];
				for (int k = 0, j = index+2 ; j <length+index+2 ;k++, j++) {
					pDNN->value[k] = decoded[j];
				}
                pN1SmInfo->pDNN = pDNN;
				pN1SmInfo->bitMask |= NAS_PDU_SESSION_DNN;
				index += length+2;
			}

			//pN1SmInfo->*p5gsmCap	
			else if (octet == 0x28) {
				std::cout << "5gsmCap: \n";
				length = decoded[index+1];
				tmNasTlvTypeT *p5gsmCap = (tmNasTlvTypeT*) 
				malloc(sizeof(tmNasTlvTypeT)+length);			//Type 4

				p5gsmCap->tag = decoded[index];
				p5gsmCap->length = decoded[index+1];
				for (int k = 0, j = index+2 ; j <length+index+2 ;k++, j++) {
					p5gsmCap->value[k] = decoded[j];
				}
				pN1SmInfo->p5gsmCap = p5gsmCap;
				pN1SmInfo->bitMask |= NAS_PDU_SESSION_5GSM_CAPABILITY;
				index += length+2; 
			}
			
			//pN1SmInfo->*pPduAddress
			else if (octet == 0x29) {
				std::cout << "PDU Address: \n";
				length =decoded[index+1];
				tmNasTlvTypeT *pPduAddress = (tmNasTlvTypeT*)
				malloc(sizeof(tmNasTlvTypeT)+length); //Type 4

 				pPduAddress->tag = decoded[index];
				pPduAddress->length = decoded[index+1];
				for (int k = 0, j = index+2 ; j <length+index+2 ;k++, j++) {
					pPduAddress->value[k] = decoded[j];
				}
				pN1SmInfo->pPduAddress = pPduAddress;
				pN1SmInfo->bitMask |= NAS_PDU_SESSION_PDU_ADDRESS;
				index += length+2; 
			} 

			//pN1SmInfo->*pBackoffTimerValue
			else if (octet == 0x37) {
				std::cout << "Back-off Timer Value \n";
				length = decoded[index+1];
				tmNasTlvTypeT *pBackoffTimerValue = (tmNasTlvTypeT*) 
				malloc(sizeof(tmNasTlvTypeT)+length);			//Type 4

				pBackoffTimerValue->tag = decoded[index];
				pBackoffTimerValue->length = decoded[index+1];
				for (int k = 0, j = index+2 ; j <length+index+2 ;k++, j++) {
					pBackoffTimerValue->value[k] = decoded[j];
				}
                pN1SmInfo->pBackoffTimerValue = pBackoffTimerValue;
				pN1SmInfo->bitMask |= NAS_PDU_SESSION_BACKOFF_TIMER_VALUE;
				index += length+2;
			}


			//pN1SmInfo->*pSmPduDnReqContainer
			else if (octet == 0x39) {
				std::cout << "pSmPduDnReqContainer: \n";
				length = decoded[index+1];
				tmNasTlvTypeT *pSmPduDnReqContainer =(tmNasTlvTypeT*) 
				malloc(sizeof(tmNasTlvTypeT)+length);				//Type 4

				pSmPduDnReqContainer->tag = decoded[index];
				pSmPduDnReqContainer->length = decoded[index+1];
				for (int k = 0, j = index+2 ; j <length+index+2 ;k++, j++) {
					pSmPduDnReqContainer->value[k] = decoded[j];
				}
				pN1SmInfo->pSmPduDnReqContainer = pSmPduDnReqContainer;
				pN1SmInfo->bitMask |= NAS_PDU_SESSION_SM_PDU_DN_REQUEST_CONTAINER;
				index += length+2; 
			}

			//pN1SmInfo->maxPktFilters
			else if (octet == 0x55) {
				std::cout << "Maximum number of supported packet filters\n"; 
				U16 mnsdf;
				octet2 = decoded[index+1];
				octet3 = decoded[index+2]; 
				octet3 = octet3 >> 5;
				mnsdf = octet2 << 3;
				mnsdf = mnsdf | octet3;
				//assigning the max no of supported filters value to the
				//pN1SmInfo object
				pN1SmInfo->maxPktFilters = mnsdf ;
				pN1SmInfo->bitMask |= NAS_PDU_SESSION_MAX_PKT_FILTERS;
				index += 3;	//for incrimenting
			}

			//pN1SmInfo->rQTimerValue
			else if (octet == 0x56) {
				std::cout << "RQ Timer Value\n";	
				for (int k = 0, j = index ; k < 2 ;k++, j++) {
					pN1SmInfo->rQTimerValue[k] = decoded[j];
				}
				pN1SmInfo->bitMask |= NAS_PDU_SESSION_RQ_TIMER_VALUE;
				index += 2;
			}

			//pN1SmInfo->gsmCause
			else if (octet == 0x59) {
				std::cout << "5GSM Cause\n"; 
				pN1SmInfo->gsmCause[0] = decoded[index];
				pN1SmInfo->gsmCause[1] = decoded[index+1];
				pN1SmInfo->bitMask |= NAS_PDU_SESSION_5GSM_CAUSE;
				index += 2;
			}

			//pN1SmInfo->p5gsmCongestionReAttemptIndicator
			else if (octet == 0x61) {
				std::cout << "5GSM Congestion Reattempt Indicator \n";
				length = decoded[index+1];
				tmNasTlvTypeT *p5gsmCongestionReAttemptIndicator = 
				(tmNasTlvTypeT*) malloc(sizeof(tmNasTlvTypeT)+length);//Type 4

				p5gsmCongestionReAttemptIndicator->tag = decoded[index];
				p5gsmCongestionReAttemptIndicator->length = decoded[index+1];
				for (int k = 0, j = index+2 ; j <length+index+2 ;k++, j++) {
					p5gsmCongestionReAttemptIndicator->value[k] = decoded[j];
				}
                pN1SmInfo->p5gsmCongestionReAttemptIndicator = 
				p5gsmCongestionReAttemptIndicator;

				pN1SmInfo->bitMask |= 
				NAS_PDU_SESSION_5GSM_CONGESTION_REATTEMPT_INDICATOR;
				
				index += length+2; 
			}


			//pN1SmInfo->pHdrCmprsnConfg
			else if (octet == 0x66) {
				std::cout << "Header compression configuration \n";
				length = decoded[index+1];
				tmNasTlvTypeT *pHdrCmprsnConfg = (tmNasTlvTypeT*) 
				malloc(sizeof(tmNasTlvTypeT)+length);	//Type 4

				pHdrCmprsnConfg->tag = decoded[index];
				pHdrCmprsnConfg->length = decoded[index+1];
				for (int k = 0, j = index+2 ; j <length+index+2 ;k++, j++) {
					pHdrCmprsnConfg->value[k] = decoded[j];
				}
                pN1SmInfo->pHdrCmprsnConfg = pHdrCmprsnConfg;
				pN1SmInfo->bitMask |= 
				NAS_PDU_SESSION_HEADER_COMPRESSION_CONFIGURATION;
				
				index += length+2; 
			}

			//pN1SmInfo->pMappedEPSBearercontext
			else if (octet == 0x75) {
				std::cout << "Mapped EPS bearer contexts\n";
				octet2 = decoded[index+1];
				octet3 = decoded[index+2];
				octet2 = octet2 << 8;
				length = octet2 | octet3;
				tmNasTlvExtendTypeT *pMappedEPSBearercontext = 
				(tmNasTlvExtendTypeT*) 
				malloc(sizeof(tmNasTlvExtendTypeT)+length);		//Type 6

				pMappedEPSBearercontext->tag = decoded[index];
				pMappedEPSBearercontext->length = length;
				for (int k = 0, j = index+3 ; j <length+index+3 ;k++, j++) {
					pMappedEPSBearercontext->value[k] = decoded[j];
				}
                pN1SmInfo->pMappedEPSBearercontext = pMappedEPSBearercontext;
				pN1SmInfo->bitMask |= NAS_PDU_SESSION_MAPPED_EPS_BEARER_CONTEXTS;
				index += length+3;
			}


			//pN1SmInfo->pEAPmsg
			else if (octet == 0x78) {
				std::cout << "EAP Message\n";
				octet2 = decoded[index+1];
				octet3 = decoded[index+2];
				octet2 = octet2 << 8;
				length = octet2 | octet3;
				tmNasTlvExtendTypeT *pEAPmsg = (tmNasTlvExtendTypeT*) 
				malloc(sizeof(tmNasTlvExtendTypeT)+length);	//Type 6

				pEAPmsg->tag = decoded[index];
				pEAPmsg->length = length;
				for (int k = 0, j = index+3 ; j <length+index+3 ;k++, j++) {
					pEAPmsg->value[k] = decoded[j];
				}
                pN1SmInfo->pEAPmsg = pEAPmsg;
				pN1SmInfo->bitMask |= NAS_PDU_SESSION_EAP_MSG;
				index += length+3;
			}

			//pN1SmInfo->pQosFlowDescriptions
			else if (octet == 0x79) {
				std::cout << "QoS Flow Descriptions\n";
				octet2 = decoded[index+1];
				octet3 = decoded[index+2];
				octet2 = octet2 << 8;
				length = octet2 | octet3;
				tmNasTlvExtendTypeT *pQosFlowDescriptions = 
				(tmNasTlvExtendTypeT*) 
				malloc(sizeof(tmNasTlvExtendTypeT)+length);		//Type 6

				pQosFlowDescriptions->tag = decoded[index];
				pQosFlowDescriptions->length = length;
				for (int k = 0, j = index+3 ; j <length+index+3 ;k++, j++) {
					pQosFlowDescriptions->value[k] = decoded[j];
				}
                pN1SmInfo->pQosFlowDescriptions = pQosFlowDescriptions;
				pN1SmInfo->bitMask |= NAS_PDU_SESSION_QOS_FLOW_DESCRIPTIONS;
				index += length+3;
			}

			//pN1SmInfo->sessionAMBR
			else if (octet == 0x2a) {
				std::cout << "Session-AMBR\n";
				for (int k = 0, j = index ; k < 8 ;k++, j++) {
					pN1SmInfo->sessionAMBR[k] = decoded[j];
				}
				pN1SmInfo->bitMask |= NAS_PDU_SESSION_AMBR;
				index += 8;
			}


			//pN1SmInfo->pQosRules
			else if (octet == 0x7a) {
				std::cout << "QoS Rules\n";
				octet2 = decoded[index+1];
				octet3 = decoded[index+2];
				octet2 = octet2 << 8;
				length = octet2 | octet3;
				tmNasTlvExtendTypeT *pQosRules = (tmNasTlvExtendTypeT*) malloc(sizeof(tmNasTlvExtendTypeT)+length);		//Type 6
				pQosRules->tag = decoded[index];
				pQosRules->length = length;
				for (int k = 0, j = index+3 ; j <length+index+3 ;k++, j++) {
					pQosRules->value[k] = decoded[j];
				}
                pN1SmInfo->pQosRules = pQosRules;
				pN1SmInfo->bitMask |= NAS_PDU_SESSION_QOS_RULES;
				index += length+3;
			}

			//pN1SmInfo->*pExtendedPCO;
			else if (octet == 0x7b) {
				std::cout << "pExtendedPCO" << '\n';
				length = decoded[index+1];
				tmNasTlvTypeT *pExtendedPCO =(tmNasTlvTypeT*) 
				malloc(sizeof(tmNasTlvTypeT)+length); //Type 4

				pExtendedPCO->tag = decoded[index];
				pExtendedPCO->length = decoded[index+1];
				for (int k = 0, j = index+2 ; j <length+index+2 ;k++, j++) {
					pExtendedPCO->value[k] = decoded[j];
				}
				pN1SmInfo->pExtendedPCO = pExtendedPCO;
				pN1SmInfo->bitMask |= NAS_PDU_SESSION_EXT_PCO;
				index += length+2; 
			}

			//pN1SmInfo->pPortManageInfoContainer
			else if (octet == 0x7c) {
				std::cout << "Port Management Information Container\n";
				octet2 = decoded[index+1];
				octet3 = decoded[index+2];
				length = octet2 << 8;
				length = length | octet3;
				tmNasTlvExtendTypeT *pPortManageInfoContainer = 
				(tmNasTlvExtendTypeT*) 
				malloc(sizeof(tmNasTlvExtendTypeT)+length);//Type 6

				pPortManageInfoContainer->tag = decoded[index];
				pPortManageInfoContainer->length = length;	//U16 length 
				
				for (int k = 0, j = index+3 ; j <length+index+3 ;k++, j++) {
					pPortManageInfoContainer->value[k] = decoded[j];
				}
				pN1SmInfo->pPortManageInfoContainer = pPortManageInfoContainer;
				pN1SmInfo->bitMask |= 
				NAS_PDU_SESSION_PORT_MANAGEMENT_INFORMATION_CONTAINER;

				index += length+3;
			}

			else {
				cout<< "none" <<endl;
			}
			
		}	

	}
	return 0;
}





U8* encodeN1SMData(U8  *pBuff ,tmNasPduSession *pN1SmInfo ) {
    //std::cout << &buffer << '\n';
    std::cout <<"<<-------------------Encoding------------------->"<<'\n';
		
    U8 *buffer = (U8*) malloc(sizeof(tmNasPduSession)); 
    int index = 0;
	U16 length;
    //Manditory terms
    buffer[index++]=pN1SmInfo->extProtoDisc;		// Extended Protocol Disc
    buffer[index++]=pN1SmInfo->pduSessionId;		// Pdus session id
    buffer[index++]=pN1SmInfo->procTxnId;		// protocol transaction id
    buffer[index++]=pN1SmInfo->msgType;			// Message type
    
    
   	//finding the message type and filling the buffer with the mainditory terms.
	U8 msgType = pN1SmInfo->msgType;

	switch (msgType) {
		
		U8 octet1,octet2;
		
		//PDU Session Establishment cases
		case 0xc1:
			std::cout << "<----PDU session establishment request----> \n";
			buffer[index++]=pN1SmInfo->intgProtectionMBR[1];
    		buffer[index++]=pN1SmInfo->intgProtectionMBR[2];
			break;

		case 0xc2:
			std::cout << "<----PDU session establishment accept---->\n";
			octet1 = pN1SmInfo->pduSessionType << 4;	//pdu sessionType
			octet2 = pN1SmInfo->sscMode;				//sscmode
			buffer[index++] = octet1 | octet2;
			//QosRules is type 6
			length = pN1SmInfo->pQosRules->length;
			buffer[index++] = length >> 8;
			buffer[index++] = length;
			for (int j = 0;j < length; j++ ) {
            	buffer[index++] = pN1SmInfo->pQosRules->value[j];
        	}
            free(pN1SmInfo->pQosRules);
			//session AMBR
			for (int k = 1; k < 8 ;k++) {
				buffer[index++] = pN1SmInfo->sessionAMBR[k];
			}
			break;

		case 0xc3:
			std::cout << "PDU session establishment reject \n";
			buffer[index++] = pN1SmInfo->gsmCause[1];		//5GSM cause
			break;

		//PDU Session Authentication cases
		case 0xc5:
			std::cout << "PDU session authentication command \n";
			//EAP msg is type 6
			length = pN1SmInfo->pEAPmsg->length;
			buffer[index++] = length >> 8;
			buffer[index++] = length;
			for (int j = 0;j < length; j++ ) {
            	buffer[index++] = pN1SmInfo->pEAPmsg->value[j];
        	}
            free(pN1SmInfo->pEAPmsg);
			break;

		case 0xc6:
			std::cout << "PDU session authentication complete \n";
			//EAP msg is type 6
			length = pN1SmInfo->pEAPmsg->length;
			buffer[index++] = length >> 8;
			buffer[index++] = length;
			for (int j = 0;j < length; j++ ) {
            	buffer[index++] = pN1SmInfo->pEAPmsg->value[j];
        	}
            free(pN1SmInfo->pEAPmsg);
			break;

		case 0xc7:
			std::cout << "PDU session authentication result \n";
			// its does not have manditory IEs than the common manditory IEs
			break;

		//PDU Session Modification cases
		case 0xc9:
			std::cout << "PDU session modification request \n";
			// its does not have manditory IEs than the common manditory IEs
			break;

		case 0xca:
			std::cout << "PDU session modification reject \n";
			buffer[index++] = pN1SmInfo->gsmCause[1];										//5GSM cause
			break;

		case 0xcb:
			std::cout << "PDU session modification command \n";
			// its does not have explicit manditory IEs than the common manditory IEs
			break;

		case 0xcc:
			std::cout << "PDU session modification complete \n";
			// its does not have explicit manditory IEs than the common manditory IEs
			break;

		case 0xcd:
			std::cout << "PDU session modification command reject \n";
			buffer[index++] = pN1SmInfo->gsmCause[1];		//5GSM cause
			break;

		case 0xd1:
			std::cout << "PDU session release request \n";
			// its does not have manditory IEs than the common manditory IEs
			break;

		case 0xd2:
			std::cout << "PDU SESSION RELEASE REJECT \n";
			buffer[index++] = pN1SmInfo->gsmCause[1];	//5GSM cause
			break;

		case 0xd3:
			std::cout << "PDU session release command \n";
			buffer[index++] = pN1SmInfo->gsmCause[1];	//5GSM cause
			break;


		case 0xd4:
			std::cout << "PDU session release complete \n";
			// its does not have manditory IEs than the common manditory IEs
			break;

		//PDU Session 5GSM status
		case 0xd6:
			std::cout << "5GSM status \n";
			buffer[index++] = pN1SmInfo->gsmCause[1];	//5GSM cause
			break;

		default:
			break;
	}


    U32 checker = pN1SmInfo->bitMask;
    //alwaysOnPduSession IEI = 8
    if (checker & NAS_PDU_SESSION_ALWAYS_ON_PDU_SESSION_INDICATION) {
		std::cout << "Always on PDU session Indication:\n";
        U8 iei = 0x8;
        U8 siei = iei << 4;
        U8 alonPduSI = pN1SmInfo->alwaysOnPduSessionIndcation;
        U8 octet = siei | alonPduSI; 
        buffer[index++] = octet;
    }

	//pduSessionType IEI = 9
    if( checker & NAS_PDU_SESSION_TYPE ) {
		std::cout << "pduSession Type\n";
        U8 iei = 0x9;
        U8 siei = iei << 4;
        U8 pduSnType = pN1SmInfo->pduSessionType;
        U8 octet = siei | pduSnType; 
        buffer[index++] = octet;
    }
	
	//sscMode IEI = a
    if ( checker & NAS_PDU_SESSION_SSC_MODE ) {
		std::cout << "ssc_mode:\n";
        U8 iei = 0xA;
        U8 siei = iei << 4;
        U8 sscmode = pN1SmInfo->sscMode;
        U8 octet = siei | sscmode; 
        buffer[index++] = octet;
    }

	//alwaysOnPduSessionReqt IEI = B
	if ( checker & NAS_PDU_SESSION_ALWAYS_ON_PDU_SESSION_REQ) {
		std::cout << "Always on PDU session Requested:\n";
        U8 iei = 0xB;
        U8 siei = iei << 4;
        U8 reqt = pN1SmInfo->alwaysOnPduSessionReqt;
        U8 octet = siei | reqt; 
        buffer[index++] = octet;
	}

	//allowedSscMode
	if ( checker & NAS_PDU_SESSION_ALLOWED_SSC_MODE ) {
		std::cout << "Allowed SSC Mode\n";
		U8 iei = 0xF;
        U8 siei = iei << 4;
        U8 sscmode = pN1SmInfo->allowedSscMode;
        U8 octet = siei | sscmode; 
        buffer[index++] = octet;
	}

    //intgProtectionMBR IEI = 13
	if (checker & NAS_PDU_SESSION_INTEGRITY_PROTECTION_MAX_DATA_RATE) {
		std::cout << "Integrity protection maximum data rate \n";
		buffer[index++] = pN1SmInfo->intgProtectionMBR[0];
		buffer[index++] = pN1SmInfo->intgProtectionMBR[1];
		buffer[index++] = pN1SmInfo->intgProtectionMBR[2];
	}
    
	//pSNSSAI IEI = 22
	if (checker & NAS_PDU_SESSION_S_NSSAI) {
		//type 4
		std::cout << "S-NSSAI\n";
		length = pN1SmInfo->pSNSSAI->length ;
        buffer[index++] = pN1SmInfo->pSNSSAI->tag;//first octet is for the IEI
        //second octet is for length                 
		buffer[index++] = pN1SmInfo->pSNSSAI->length;
        for (int j = 0;j < length; j++ ) {
            buffer[index++] = pN1SmInfo->pSNSSAI->value[j];
        }
        free(pN1SmInfo->pSNSSAI);
	}
    
	//pDNN
	if (checker & NAS_PDU_SESSION_DNN) {
		//type 4
		std::cout << "DNN\n";
		length = pN1SmInfo->pDNN->length ;
        buffer[index++] = pN1SmInfo->pDNN->tag;//first octet is for the IEI
		//second octet is for length                 
        buffer[index++] = pN1SmInfo->pDNN->length;
        for (int j = 0;j < length; j++ ) {
            buffer[index++] = pN1SmInfo->pDNN->value[j];
        }
        free(pN1SmInfo->pDNN);
	}

    //p5gsmCap IEI = 28
    if (checker & NAS_PDU_SESSION_5GSM_CAPABILITY) {
		//type 4
		std::cout << "5gsmCap: \n";
        length = pN1SmInfo->p5gsmCap->length ;
		//first octet is for the IEI
		buffer[index++] = pN1SmInfo->p5gsmCap->tag;  
		//second octet is for length               
		buffer[index++] = pN1SmInfo->p5gsmCap->length;
        for (int j = 0;j < length; j++ ) {
            buffer[index++] = pN1SmInfo->p5gsmCap->value[j];
        }
        free(pN1SmInfo->p5gsmCap);
    }

	//pPduAddress IEI = 29
	if (checker & NAS_PDU_SESSION_PDU_ADDRESS) {
		//type 4
		std::cout << "PDU Address: \n";
		length = pN1SmInfo->pPduAddress->length ;
		//first octet is for the IEI
        buffer[index++] = pN1SmInfo->pPduAddress->tag;
		//second octet is for length                 
        buffer[index++] = pN1SmInfo->pPduAddress->length;
        for (int j = 0;j < length; j++ ) {
            buffer[index++] = pN1SmInfo->pPduAddress->value[j];
        }
        free(pN1SmInfo->pPduAddress);
	}

	//pBackoffTimerValue IEI = 37
	if (checker & NAS_PDU_SESSION_BACKOFF_TIMER_VALUE) {
		//type 4
		std::cout << "BackoffTimerValue \n";
        length = pN1SmInfo->pBackoffTimerValue->length ;
		//first octet is for the IEI
        buffer[index++] = pN1SmInfo->pBackoffTimerValue->tag;
		//second octet is for length                 
        buffer[index++] = pN1SmInfo->pBackoffTimerValue->length;
        for (int j = 0;j < length; j++ ) {
            buffer[index++] = pN1SmInfo->pBackoffTimerValue->value[j];
        }		
        free(pN1SmInfo->pBackoffTimerValue);
	}

    //pSmPduDnReqContainer IEI = 39
    if (checker & NAS_PDU_SESSION_SM_PDU_DN_REQUEST_CONTAINER) {
		std::cout << "pSmPduDnReqContainer: \n";
        length = pN1SmInfo->pSmPduDnReqContainer->length ;
		//first octet is for the IEI
        buffer[index++] = pN1SmInfo->pSmPduDnReqContainer->tag;
		//second octet is for length                 
        buffer[index++] = pN1SmInfo->pSmPduDnReqContainer->length;
        for (int j = 0;j < length; j++ ) {
            buffer[index++] = pN1SmInfo->pSmPduDnReqContainer->value[j];
        }
        free(pN1SmInfo->pSmPduDnReqContainer);
    }
 
    //maxPktFilters IEI = 55
    if (checker & NAS_PDU_SESSION_MAX_PKT_FILTERS) {
		std::cout << "Maximum number of supported packet filters\n"; 
        U8 iei = 0x55;
        length = pN1SmInfo->maxPktFilters ;
        U8 len_octet1 = length >> 3;        
        U16 octet = length << 13;
        U8 len_octet2 = octet >> 8;  
        buffer[index++] = iei;                   //first octet is for the IEI
        buffer[index++] = len_octet1;
        buffer[index++] = len_octet2;//second and third octet is for length
    }

	//rQTimerValue IEI = 56
	if (checker & NAS_PDU_SESSION_RQ_TIMER_VALUE) {
		std::cout << "RQ Timer Value\n";	
		buffer[index++] = pN1SmInfo->rQTimerValue[0];
		buffer[index++] = pN1SmInfo->rQTimerValue[1];
	}

	//gsmCause IEI = 59
	if (checker & NAS_PDU_SESSION_5GSM_CAUSE) {
		std::cout << "5GSM Cause \n";
		buffer[index++] = pN1SmInfo->gsmCause[0];	//first octet is IEI
		buffer[index++] = pN1SmInfo->gsmCause[1];   //second octet is 5GSM Cause
	}

	//p5gsmCongestionReAttemptIndicator IEI = 61
	if (checker & NAS_PDU_SESSION_5GSM_CONGESTION_REATTEMPT_INDICATOR) {
		//type 4
		std::cout << "p5gsmCongestionReAttemptIndicator" << '\n';
        length = pN1SmInfo->p5gsmCongestionReAttemptIndicator->length ;
		//first octet is for the IEI
        buffer[index++] = pN1SmInfo->p5gsmCongestionReAttemptIndicator->tag;
		//second octet is for length                 
        buffer[index++] = pN1SmInfo->p5gsmCongestionReAttemptIndicator->length;
        for (int j = 0;j < length; j++ ) {
            buffer[index++] = pN1SmInfo->p5gsmCongestionReAttemptIndicator->value[j];
        }
        free(pN1SmInfo->p5gsmCongestionReAttemptIndicator);
	}

	//pHdrCmprsnConfg IEI = 66
	if (checker & NAS_PDU_SESSION_HEADER_COMPRESSION_CONFIGURATION) {
		//type 4
		std::cout << "Header compression configuration \n";
        length = pN1SmInfo->pHdrCmprsnConfg->length ;
		//first octet is for the IEI
        buffer[index++] = pN1SmInfo->pHdrCmprsnConfg->tag;
		//second octet is for length                 
        buffer[index++] = pN1SmInfo->pHdrCmprsnConfg->length;
        for (int j = 0;j < length; j++ ) {
            buffer[index++] = pN1SmInfo->pHdrCmprsnConfg->value[j];
        }
        free(pN1SmInfo->pHdrCmprsnConfg);
	}

	//pMappedEPSBearercontext IEI = 75
	if (checker & NAS_PDU_SESSION_MAPPED_EPS_BEARER_CONTEXTS) {
		//type 6
		std::cout << "Mapped EPS bearer contexts\n";
        length = pN1SmInfo->pMappedEPSBearercontext->length ;
		//first octet is for the IEI
        buffer[index++] = pN1SmInfo->pMappedEPSBearercontext->tag;
		//second and third octet is for length                 
		buffer[index++] = pN1SmInfo->pMappedEPSBearercontext->length >> 8;
		buffer[index++] = pN1SmInfo->pMappedEPSBearercontext->length;
        for (int j = 0;j < length; j++ ) {
            buffer[index++] = pN1SmInfo->pMappedEPSBearercontext->value[j];
        }
        free(pN1SmInfo->pMappedEPSBearercontext);
	}

	//pEAPmsg IEI = 78
	if (checker & NAS_PDU_SESSION_EAP_MSG) {
		//type 6
		std::cout << "pEAPmsg" << '\n';
        length = pN1SmInfo->pEAPmsg->length ;
		//first octet is for the IEI
        buffer[index++] = pN1SmInfo->pEAPmsg->tag;
		//second and third octet is for length
		buffer[index++] =  pN1SmInfo->pEAPmsg->length >> 8;
		buffer[index++] = pN1SmInfo->pEAPmsg->length;                 
        for (int j = 0;j < length; j++ ) {
            buffer[index++] = pN1SmInfo->pEAPmsg->value[j];
        }
        free(pN1SmInfo->pEAPmsg);
	}

	//pQosFlowDescriptions IEI = 79
	if (checker & NAS_PDU_SESSION_QOS_FLOW_DESCRIPTIONS) {
		//type 6
		std::cout << "QoS Flow Descriptions\n";
        length = pN1SmInfo->pQosFlowDescriptions->length ;
		//first octet is for the IEI
        buffer[index++] = pN1SmInfo->pQosFlowDescriptions->tag;
		//second and third octet is for length                 
		buffer[index++] = pN1SmInfo->pQosFlowDescriptions->length >> 8;
		buffer[index++] = pN1SmInfo->pQosFlowDescriptions->length;
        for (int j = 0;j < length; j++ ) {
            buffer[index++] = pN1SmInfo->pQosFlowDescriptions->value[j];
        }
        free(pN1SmInfo->pQosFlowDescriptions);
	}

	//sessionAMBR IEI = 2a
	if (checker & NAS_PDU_SESSION_AMBR) {
		std::cout << "Session-AMBR\n";
		for (int k = 0; k < 8 ;k++) {
			buffer[index++] = pN1SmInfo->sessionAMBR[k];
		}
	}
 
	//pQosRules IEI = 7a
	if (checker & NAS_PDU_SESSION_QOS_RULES) {
		//type 6
		std::cout << "QoS Rules\n";
		length = pN1SmInfo->pQosRules->length ;
		//first octet is for the IEI
        buffer[index++] = pN1SmInfo->pQosRules->tag; 
		//second and third octet is for length                          
		buffer[index++] = pN1SmInfo->pQosRules->length >> 8;        
		buffer[index++] = pN1SmInfo->pQosRules->length;                    						     
        for (int j = 0;j < length; j++ ) {
            buffer[index++] = pN1SmInfo->pQosRules->value[j];
        }
        free(pN1SmInfo->pQosRules);
	}

    //pExtendedPCO IEI = 7b
    if (checker & NAS_PDU_SESSION_EXT_PCO) {
		std::cout << "pExtendedPCO" << '\n';
        length = pN1SmInfo->pExtendedPCO->length ;
		//first octet is IEI
        buffer[index++] = pN1SmInfo->pExtendedPCO->tag;
		//second octet is for length                 
        buffer[index++] = pN1SmInfo->pExtendedPCO->length;
        for (int j = 0 ; j < length; j++ ) {
            buffer[index++] = pN1SmInfo->pExtendedPCO->value[j];
        }
        free(pN1SmInfo->pExtendedPCO);
    }

	//pPortManageInfoContainer IEI = 7c
	if (checker & NAS_PDU_SESSION_PORT_MANAGEMENT_INFORMATION_CONTAINER) {
		//type 6
		std::cout << "Port Manage Info Container" << '\n';
        length = pN1SmInfo->pPortManageInfoContainer->length ;
		//first octet is for the IEI
        buffer[index++] = pN1SmInfo->pPortManageInfoContainer->tag;
		//second and third octet is for length                 
		buffer[index++] = pN1SmInfo->pPortManageInfoContainer->length >> 8;
		buffer[index++] = pN1SmInfo->pPortManageInfoContainer->length;
        for (int j = 0;j < length; j++ ) {
            buffer[index++] = pN1SmInfo->pPortManageInfoContainer->value[j];
        }
        free(pN1SmInfo->pPortManageInfoContainer);
	}
	
	U8* decoded = buffer;
	string encoded;
	
	CryptoPP::HexEncoder encoder;
	encoder.Put(decoded, index);
	encoder.MessageEnd();
	
	CryptoPP::word64 size = encoder.MaxRetrievable();
	if(size)
	{
    	encoded.resize(size);		
    	encoder.Get((CryptoPP::byte*)&encoded[0], encoded.size());
	}
	
	pBuff = (U8*) malloc(2*index*sizeof(U8));
	for(int j=0; encoded[j] != '\0'  ; j++)
	{
		pBuff[j]=encoded[j];
	}
	free(buffer);
    return pBuff;  

}

//main function
int main() {
	//U8  buffer[] = "2E0509C1FFFF93A1B055AA2E28012E39007b0201017C000111";// buffer for PDU session establishment request
	U8 buffer[] = "2E0509C21100011111223344556677590129092233445566778899115611220911111111111111111181750009111111111111111111780009111111111111111111790009111111111111111111250911111111111111111166091111111111111111117B0F665544332211111111111111111111";
	//U8 buffer[] = "2E0509C2110001111122334455667759012901115611220111817500011178000111790001112501116601117B0111";//PDU Session establishment Accept
	//U8 buffer[] = "2E0509C301370111F1780001117B0111610111";//PDU Session Establishment Reject
	//U8 buffer[] = "2E0509C50001007B0111";	//PDU session authentication command
	//U8 buffer[] = "2E0509C60001007B0111";	//PDU session authentication complete
	//U8 buffer[] = "2E0509C7780001007B0111";	//PDU session authentication result
	//U8 buffer[] = "2E0509C9132233B128011159015500207B01117A00011179000111750001117C000111"; //PDU session modification request
	//U8 buffer[] = "2E0509CA013701007B0111610100"; //PDU session modification reject
	//U8 buffer[] = "2E0509CB59012A112233445566775612817A00010075000123790001117B01116601117C000111";//PDU Modification Command
	//U8 buffer[] = "2E0509CC7B01117C000111";//PDU session modification complete
	//U8 buffer[] = "2E0509CD117B0111"; //PDU session modification command reject
	//U8 buffer[] = "2E0509D159117B0111"; //PDU session release request
	//U8 buffer[] = "2E0509D2117B0100"; //PDU SESSION RELEASE REJECT 
	//U8 buffer[] = "2E0509D301370100780001016101117B0100"; // PDU session Release Command
	//U8 buffer[] = "2E0509D459017B01AA"; // PDU session Release Complete
	//U8 buffer[] = "2E0509D601"; //5GSM Status
	tmNasPduSession data;
	//----------------------------------Decoding-----------------------------------------
	decodeN1SMData(buffer, &data); 
    //----------------------------------Encoding------------------------------------------
    U8 *enbuffer = NULL; 
    enbuffer = encodeN1SMData(enbuffer, &data);
    std::cout << enbuffer << '\n';
    free(enbuffer);

	return 0;
}