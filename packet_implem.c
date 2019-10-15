#include "packet_interface.h"
#include <arpa/inet.h>
#include <stdlib.h>
#include <stdio.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <zlib.h>
#define min(a,b) (a<=b?a:b)

/* Extra #includes */
/* Your code will be inserted here */
struct __attribute__((__packed__)) pkt {
    uint8_t type:2;
    uint8_t tr:1;
    uint8_t window:5;
    uint8_t *length;
    uint8_t seqnum;
    uint32_t timestamp;
    uint32_t crc1;
    char *payload;
    uint32_t crc2;
};

/* Extra code */
/* Your code will be inserted here */

pkt_t* pkt_new()
{
    pkt_t* pkg = (pkt_t*)calloc(1,sizeof(pkt_t));
    if (pkg==NULL) {
        return NULL;
    }
    pkg->payload = NULL;
    return pkg;
}

void pkt_del(pkt_t *pkt)
{
    if(pkt_get_length(pkt)>0){
      free(pkt->payload);
    }
    free(pkt);
}


pkt_status_code pkt_decode(const char *data, const size_t len, pkt_t *pkt)
{
    pkt_status_code verif;
    if(len<(11*sizeof(uint8_t))){
        return E_NOHEADER;
    }
    pkt->length = (uint8_t*)malloc(sizeof(uint8_t));
    if((pkt->length) == NULL){
        return -1;
    }
    memcpy(pkt, data, 1);
    memcpy(&((pkt->length)[0]), &(data[1]), 1);
    if(((pkt->length)[0] & 0b10000000) == 0b10000000 ){
    	if(realloc((pkt->length),2*sizeof(uint8_t)) == NULL){
            return -1;
        }
        memcpy(&((pkt->length)[1]), &(data[2]), 1);
    }
    ssize_t taille = predict_header_length(pkt);
    
    if(taille==7){
        uint8_t seqnum = (uint8_t)data[2];
        verif = pkt_set_seqnum(pkt, seqnum);
        if(verif != PKT_OK)
            return verif;
    }
    else{
        uint8_t seqnum = (uint8_t)data[3];
        verif = pkt_set_seqnum(pkt, seqnum);
        if(verif != PKT_OK)
            return verif;
    }
    
    if(taille==7){
        uint32_t timestamp = (uint32_t) *(data + 3);
        verif = pkt_set_timestamp(pkt, timestamp);
        if(verif != PKT_OK)
            return verif;
    }
    else{
        uint32_t timestamp = (uint32_t) *(data + 4);
        verif = pkt_set_timestamp(pkt, timestamp);
        if(verif != PKT_OK)
            return verif;
    }
    
    if(taille==7){
        uint32_t crc1bis = (uint32_t) *(data + 7);
        
        crc1bis = ntohl(*((uint32_t *)(data + 8)));

		uint32_t new_crc1 = crc32(0L, Z_NULL, 0);

		new_crc1 = crc32(new_crc1,(const Bytef*) data, 8);


		if(crc1bis != new_crc1)
			return E_CRC;
        verif = pkt_set_crc1(pkt, crc1bis);
        if(verif != PKT_OK)
            return verif;
    }
    
    else{
        uint32_t crc1bis = (uint32_t) *(data + 8);
        verif = pkt_set_crc1(pkt, crc1bis);
    }
    
    if(taille==7){
        verif = pkt_set_payload(pkt, (data + 11), *(pkt->length));
        if(verif != PKT_OK)
            return verif;
    }
    else{
        verif = pkt_set_payload(pkt, (data + 12), *(pkt->length));
        if(verif != PKT_OK)
            return verif;
    }
    if(taille==7){
        if(&(data[(pkt_get_length(pkt))+11])!=NULL){
            uint32_t crc2bis = (uint32_t) *(data + ((pkt_get_length(pkt))+11));
        
        	crc2bis = ntohl(*((uint32_t *)(data + ((pkt_get_length(pkt))+12))));
            uint32_t new_crc2 = crc32(0L, Z_NULL, 0);

			new_crc2 = crc32(new_crc2,(const Bytef*) data, 8);


			if(crc2bis != new_crc2)
			return E_CRC;
            verif = pkt_set_crc2(pkt, *(data+(11+pkt_get_length(pkt))));
            if(verif != PKT_OK)
                return verif;
        }
    }
    else{
        if(&(data[(pkt_get_length(pkt))+12])!=NULL){
            uint32_t crc2 = (uint32_t) *(data + ((pkt_get_length(pkt))+12));
        
        	crc2 = ntohl(*((uint32_t *)(data + ((pkt_get_length(pkt))+13))));
            uint32_t new_crc2 = crc32(0L, Z_NULL, 0);

			new_crc2 = crc32(new_crc2,(const Bytef*) data, 8);


			if(crc2 != new_crc2)
			return E_CRC;
            verif = pkt_set_crc2(pkt, *(data+(12+pkt_get_length(pkt))));
            if(verif != PKT_OK)
                return verif;
        }
    }
    	return verif;
}


pkt_status_code pkt_encode(const pkt_t* pkt, char *buf, size_t *len)
{
    size_t count=1;
    if((*len)<count){
        return -1;
    }
    memcpy(buf, pkt, 1);
    if(predict_header_length(pkt)==7){
        count+=1;
        if((*len)<count){
            return -1;
        }
        memcpy(buf, pkt->length, 1);
    }
    else{
        count+=1;
        if((*len)<count){
            return -1;
        }
        memcpy(buf, pkt->length, 1);
    }
    count+=1;
    if((*len)<count){
    return -1;
    }
    memcpy(buf, &(pkt->seqnum), 1);
    count+=4;
    if((*len)<count){
        return -1;
    }
    memcpy(buf, &(pkt->timestamp), 4);
    count+=4;
    if((*len)<count){
        return -1;
    }
    memcpy(buf, &(pkt->crc1), 4);
    uint16_t length=pkt_get_length(pkt);
    count+=length;
    if((*len)<count){
        return -1;
    }
    memcpy(buf, pkt->payload, length);
    if(pkt_get_crc2(pkt)!=0){
        count+=4;
        if((*len)<count){
            return -1;
        }
        memcpy(buf, &(pkt->crc2), 4);
    }
    return PKT_OK;
}

ptypes_t pkt_get_type  (const pkt_t* pkt)
{
    ptypes_t type = pkt->type;
    return type;

}

uint8_t  pkt_get_tr(const pkt_t* pkt)
{
    return pkt->tr;
}

uint8_t  pkt_get_window(const pkt_t* pkt)
{
    return pkt->window;
}

uint8_t  pkt_get_seqnum(const pkt_t* pkt)
{
    return pkt->seqnum;
}

uint16_t pkt_get_length(const pkt_t* pkt)
{
    if(((pkt->length)[0] & 0b10000000) == 0b10000000){
        uint16_t len = (pkt->length)[1];
        uint16_t len2=(uint16_t) (pkt->length)[0];
        uint16_t len3 = (len2)<<9;
        len3=(len3)>>1;
        return len3+len;
    }
    else{
        uint16_t len=*(pkt->length);
        len=len<<1;
        len=len>>1;
        return len;
    }
}

uint32_t pkt_get_timestamp   (const pkt_t* pkt)
{
    return (pkt->timestamp);
}

uint32_t pkt_get_crc1   (const pkt_t* pkt)
{
    return pkt->crc1;
}

uint32_t pkt_get_crc2   (const pkt_t* pkt)
{
    if (pkt->crc2 != 0) {
        return pkt->crc2;
    }
    return 0;
}

const char* pkt_get_payload(const pkt_t* pkt)
{
    return pkt->payload;
}


pkt_status_code pkt_set_type(pkt_t *pkt, const ptypes_t type)
{
    pkt->type = (uint8_t)type;
    return PKT_OK;
}

pkt_status_code pkt_set_tr(pkt_t *pkt, const uint8_t tr)
{
    pkt->tr = tr;
    return PKT_OK;
}

pkt_status_code pkt_set_window(pkt_t *pkt, const uint8_t window)
{
    if(sizeof(window)>MAX_WINDOW_SIZE){
        return E_WINDOW;
    }
    pkt->window= window;
    return PKT_OK;
}

pkt_status_code pkt_set_seqnum(pkt_t *pkt, const uint8_t seqnum)
{
    pkt->seqnum = seqnum;
    return PKT_OK;
}

pkt_status_code pkt_set_length(pkt_t *pkt, const uint16_t length)
{
    if((length&0b1000000000000000)==0b1000000000000000){
        return E_LENGTH;
    }
    if((length&0b1111111100000000)!=0b0000000000000000){
        pkt->length=(uint8_t *) malloc(2*sizeof(uint8_t));
        (pkt->length)[0]=(length & 0b11111111);
        (pkt->length)[0]=(((pkt->length)[0])|0b1000000000000000);
        (pkt->length)[1]=(length&0b0000000011111111);
    }
    else{
        pkt->length=(uint8_t *) malloc(sizeof(uint8_t));
        *(pkt->length)=length;
    }
    return PKT_OK;
}

pkt_status_code pkt_set_timestamp(pkt_t *pkt, const uint32_t timestamp)
{
    pkt->timestamp = (timestamp);
    return PKT_OK;
}

pkt_status_code pkt_set_crc1(pkt_t *pkt, const uint32_t crc1)
{
    pkt->crc1 = crc1;
    return PKT_OK;
}

pkt_status_code pkt_set_crc2(pkt_t *pkt, const uint32_t crc2)
{
    pkt->crc2=crc2;
    return PKT_OK;
}

pkt_status_code pkt_set_payload(pkt_t *pkt,
                                const char *data,
                                const uint16_t length)
{
    uint16_t newLength = min(length, MAX_PAYLOAD_SIZE);
    pkt->payload = (char*)malloc(sizeof(char)* newLength);
    if(pkt->payload==NULL){
        return E_NOMEM;
    }
    memcpy(pkt->payload,data,newLength);

    return pkt_set_length(pkt,newLength);
}

ssize_t varuint_decode(const uint8_t *data, const size_t len, uint16_t *retval){
    if(len<1){
        return -1;
    }
    if(len == 1){
        uint16_t *val=(uint16_t *) malloc(sizeof(uint16_t));
        if(val==NULL){
            return -1;
        }
        val=(uint16_t*) data;
        uint16_t * datah = (uint16_t *) malloc(len*sizeof(uint16_t));
        *datah=(ntohs(*val));
        memcpy(retval, datah, 2);
        return 1;
    }
    uint16_t interval=((0b0111111111111111)&(*data));
    uint16_t *val=(uint16_t *) malloc(sizeof(uint16_t));
    if(val==NULL){
        return -1;
    }
    val=&interval;
    uint16_t *valh= (uint16_t *)malloc(sizeof(uint16_t));
    if(valh == NULL){
        return -1;
    }
    uint16_t val2 = ntohs(*val);
    valh= (uint16_t *)(&val2);
    memcpy(retval, valh, 2);
    return 2;
 }



ssize_t varuint_encode(uint16_t val, uint8_t *data, const size_t len){
    if(varuint_predict_len(val)> (ssize_t)len){
        return -1; //taille de data trop petite
    }
    if(varuint_predict_len(val) == 1){
        uint8_t *valp =(uint8_t *) malloc(sizeof(uint8_t));
        if(valp == NULL){
            return -1;
        }
        uint8_t vals = (uint8_t) val;
        *valp = htons(vals);
        memcpy(data, valp, 1);
        return 1;
    }
    uint16_t *valp =(uint16_t *) malloc(sizeof(uint16_t));
    if(valp == NULL){
        return -1;
    }
    uint16_t val2 = htons(val);
    valp = &val2;
    memcpy(data, valp, 2);
    return 2;
}



size_t varuint_len(const uint8_t *data){
    uint8_t *data1 = malloc(sizeof(uint8_t));
    memcpy(data1, data, sizeof(uint8_t));
    uint8_t *data2 = malloc(sizeof(uint8_t));
    memcpy(data2, data, 1+sizeof(uint8_t));
    if(data2 == NULL){
        return 1;
    }
    return 2;
}


ssize_t varuint_predict_len(uint16_t val){
    if(val >= 0x8000){
        return -1;
    }
    if((val&0b1000000000000000)==0b1000000000000000){
        return 2;
    }
    return 1;
    
}



ssize_t predict_header_length(const pkt_t *pkt){
    uint16_t length = pkt_get_length(pkt);
    if(length > 0x8000){
        return -1;
    }
    ssize_t length_size = varuint_predict_len(length);
    ssize_t taille=6+length_size;
    return taille;
}
