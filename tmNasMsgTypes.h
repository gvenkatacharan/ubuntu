#ifndef __TM_NAS_MSG_TYPES_H__
#define __TM_NAS_MSG_TYPES_H__

#include "tmCmnTypes.h"

//Type 4
typedef struct {
      U8         tag;
      U8         length;
      U8         padding;
      U8         value[];
} tmNasTlvTypeT;


//Type 6
typedef struct {
      U8          tag;
      U16          length;
      U8          padding;
      U8          value[];
}tmNasTlvExtendTypeT;

typedef struct {
      // 3GPP 24.501 Section 8.3.1 (PDU Session Establishment Request)
      // -------------------------------------------------------------
      //
      // Mandatory fields and common in all the NasMsg
      U8         extProtoDisc;          // Extended Protocol Discriminator
      U8         pduSessionId;          // PDU Session ID
      U8         procTxnId;             // Procedure Transaction Identity
      U8         msgType;               // Message Type (0xC1 -->  Sess Est Req)


      //Manditory but not common in all
      U8                    intgProtectionMBR[3]; // Integrity protection maximum data rate
      U8                    pduSessionType;             // PDU session type
      U8                    sscMode;                    // SSC mode
      U8                    sessionAMBR[8];             // Session-AMBR
      U8                    gsmCause[2];                // 5GSM cause
      tmNasTlvExtendTypeT   *pEAPmsg;                   // EAP message
      tmNasTlvExtendTypeT   *pQosRules;                 // QoS rules


      // Optional fields
      U32                         bitMask = 0;
#define NAS_PDU_SESSION_TYPE                                    0x0001
#define NAS_PDU_SESSION_SSC_MODE                                0x0002
#define NAS_PDU_SESSION_5GSM_CAPABILITY                         0x0004
#define NAS_PDU_SESSION_MAX_PKT_FILTERS                         0x0008
#define NAS_PDU_SESSION_ALWAYS_ON_PDU_SESSION_REQ               0x0010
#define NAS_PDU_SESSION_SM_PDU_DN_REQUEST_CONTAINER             0x0020
#define NAS_PDU_SESSION_EXT_PCO                                 0x0040      
#define NAS_PDU_SESSION_EAP_MSG                                 0X0080 
#define NAS_PDU_SESSION_5GSM_CAUSE                              0X0100
#define NAS_PDU_SESSION_AMBR                                    0x0200
#define NAS_PDU_SESSION_QOS_RULES                               0x0400
#define NAS_PDU_SESSION_INTEGRITY_PROTECTION_MAX_DATA_RATE      0x0800
#define NAS_PDU_SESSION_ALWAYS_ON_PDU_SESSION_INDICATION        0x1000
#define NAS_PDU_SESSION_RQ_TIMER_VALUE                          0x2000
#define NAS_PDU_SESSION_BACKOFF_TIMER_VALUE                     0x4000
#define NAS_PDU_SESSION_ALLOWED_SSC_MODE                        0x8000
#define NAS_PDU_SESSION_HEADER_COMPRESSION_CONFIGURATION        0x10000
#define NAS_PDU_SESSION_PORT_MANAGEMENT_INFORMATION_CONTAINER   0x20000
#define NAS_PDU_SESSION_PDU_ADDRESS                             0x40000
#define NAS_PDU_SESSION_S_NSSAI                                 0x80000
#define NAS_PDU_SESSION_MAPPED_EPS_BEARER_CONTEXTS              0x100000
#define NAS_PDU_SESSION_QOS_FLOW_DESCRIPTIONS                   0x200000
#define NAS_PDU_SESSION_DNN                                     0x400000
#define NAS_PDU_SESSION_5GSM_CONGESTION_REATTEMPT_INDICATOR     0x800000
      
      U16                   maxPktFilters;// Max no of supported packet filters
      // Always-on PDU session requested
      U8                    alwaysOnPduSessionReqt;
      // Always-on PDU session indication
      U8                    alwaysOnPduSessionIndcation;
      U8                    rQTimerValue[2]; // GPRS timer 
      tmNasTlvTypeT         *pBackoffTimerValue; // Back-off timer value
      U8                    allowedSscMode; // allowed SSC Mode
      tmNasTlvTypeT         *p5gsmCap; // 5GSM capability 
      tmNasTlvTypeT         *pSmPduDnReqContainer;// SM PDU DN reqt container 
      tmNasTlvTypeT         *pExtendedPCO; // Extended protocol config options 
      tmNasTlvTypeT         *pHdrCmprsnConfg; // Header compression config
      tmNasTlvTypeT         *pPduAddress; // PDU address
      tmNasTlvTypeT         *pSNSSAI; // S-NSSAI
      tmNasTlvTypeT         *pDNN; // DNN
      // 5GSM COngestion Reattempt indicator
      tmNasTlvTypeT         *p5gsmCongestionReAttemptIndicator;
      // Port management information container
      tmNasTlvExtendTypeT   *pPortManageInfoContainer;
      tmNasTlvExtendTypeT   *pQosFlowDescriptions;// QoS flow descriptions
      // Mapped EPS bearer contexts
      tmNasTlvExtendTypeT   *pMappedEPSBearercontext;

}tmNasPduSession;

#endif
