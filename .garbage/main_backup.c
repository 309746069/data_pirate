#include <stdlib.h>
#include <stdio.h>
#include <libnet.h>
#include <pcap.h>
#include <pthread.h>

#include "robber.h"
/*the printer running when packet have captured*/



void
package_dispatch(   u_char                      *userarg,   // callback args
                    const struct pcap_pkthdr    *pkthdr,    // packet info
                    const u_char                *packet)    // packet buf
{
    // fprintf(stdout, "%d\n", pkthdr->len);

    // int i=0;
    // if(pkthdr->len < 0x100) return;

    // do
    // {
    //     if(!(i%16)) printf("\n");
    //     printf("%02X ", packet[i]);
    // }while(i++ < pkthdr->len);
    // printf("%s\n", packet+0x37);
    
    robber(packet, pkthdr->len);

    printf("\n==============================\n\n\n");
}


void
thr_fn(void)
{
    char a[500000]  = {0};
    printf("%s\n", a);

    char* p = 0;
    p = malloc(5000000);
    memset(p, 0, 5000000);
    printf("%s\n", p);


    pthread_setcanceltype(PTHREAD_CANCEL_DISABLE, 0);
    static int i=1;
    while(1)
    {
        printf("%d\n", i++);
        // pthread_testcancel();
        sleep(1);
    }
    printf("thread finish\n");
}


void
thread_test(void)
{


    clock_t start, finish;  
    double  duration;  
 


    int i=0;
    int err;
    pthread_t ntid[3000];

    start = clock();  


    for(i=0;i<sizeof(ntid)/sizeof(*ntid);i++)
        err = pthread_create(ntid+i, NULL, thr_fn, NULL);

    finish = clock();  

    duration = (double)(finish - start) / CLOCKS_PER_SEC;  
    printf( "%f seconds\n", duration );
    
    getchar();

    start = clock();  
    for(i=0;i<sizeof(ntid)/sizeof(*ntid); i++)
    {
        if(pthread_cancel(ntid[i]))
        {
            printf("kill failed\n");
        }
    }

    finish = clock();  

    duration = (double)(finish - start) / CLOCKS_PER_SEC;  
    printf( "%f seconds\n", duration );
    


    start = clock();  

    void* p = malloc(10000);
    memset(p, 0, 10000);
    printf("%p\n", p);

    memcpy(p, ntid, sizeof(ntid));
    printf("===========%d\n", sizeof(ntid));


    finish = clock();  

    duration = (double)(finish - start) / CLOCKS_PER_SEC;  
    printf( "%f seconds\n", duration );
    



    // pthread_join();
    printf("==============\n");

    sleep(5);


}







int main (int argc, char* argv[])
{
    _SET_LOG_OUT_FUN(printf);
#if 1
    // printf("is this right?");
    /*the error code buf of libpcap*/
    char ebuf[PCAP_ERRBUF_SIZE];
    /*create capture handler of libpcap*/
    pcap_t *pd = pcap_open_live (pcap_lookupdev(ebuf), 68, 0, 1000, ebuf);

    /*start the loop of capture, loop 5 times, enter printer when capted*/
    pcap_loop (pd, 300, package_dispatch, NULL);

    pcap_close (pd);
#endif

    pthread_t pthread_id;  
    pthread_attr_t thread_attr;  
    int status;  
  

    status = pthread_attr_init(&thread_attr);  
    if(status != 0)  
        printf("init error\n");  
  
    size_t stacksize = 100;  
    status = pthread_attr_getstacksize(&thread_attr, &stacksize);  
    printf("stacksize(%d)\n", stacksize);  
    printf("%p", printf);


    thread_test();



    return 0;
}





// int
// main(const int argc, const char* argv[])
// {
//     char errBuf[PCAP_ERRBUF_SIZE], * device;

//     device = pcap_lookupdev(errBuf);

//     if(device)
//     {
//         printf("success: device: %s\n", device);
//     }
//     else
//     {
//         printf("error: %s\n", errBuf);
//     }


//     send();






//     return 0;
// }