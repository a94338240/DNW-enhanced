/* 
   Author: David Wu
   Email: david@pocograph.com
 */

/* ----- HEADER BEGIN ----- */
#include <libusb.h>

#define MAX_USB_PIPES (255)
typedef void (* usb_filter_cb_func_t)(libusb_device *device);

enum USB_DEVICE_FILTER_t {
  USB_DEV_FILTER_BY_PVID,
};

enum USB_PIPES_TYPE_t {
  USB_PIPE_TYPE_CONTROL,
  USB_PIPE_TYPE_ISOCHRONOUS,
  USB_PIPE_TYPE_BULK,
  USB_PIPE_TYPE_INTERRUPT
};

struct usb_device_filter_pvid_t {
  unsigned int vendor_id;
  unsigned int product_id;
};

struct usb_transfer_pipe_t {
  struct libusb_device_handle *dev_handle;
  enum USB_PIPES_TYPE_t type;
  unsigned char interface_number;
  unsigned char endpoint;
};

#define BLOCK_SIZE (512)

/* ----- HEADER END ----- */

#include <stdio.h>
#include <getopt.h>
#include <string.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/types.h>

static char *speed_to_string_tbl[] = {
  "UNKNOWN",
  "LOW (1.5 BMps)",
  "FULL (12 MBps)",
  "HIGH (480 MBps)",
  "SUPER (5 GBps)"
};

static char *endpoint_type_string_tbl[] = {
  "CONTROL",
  "ISOCHRONOUS",
  "BULK",
  "INTERRUPT"
};

static char *endpoint_dir_string_tbl[] = {
  "OUT",
  "IN"
};

struct usb_transfer_pipe_t usb_in_pipes[MAX_USB_PIPES] = {0};
struct usb_transfer_pipe_t usb_out_pipes[MAX_USB_PIPES] = {0};

char *filename = NULL;

static int usb_device_transfer()
{
  int retval = 0, found = 0, i = 0, j = 0, transfered = 0, 
    total_transfered = 0, res = -9;
  unsigned char *data_to_transfer, *p = NULL, *pe = NULL;
  FILE *fp = NULL;
  int real_read = 0, to_write = 0;
  uint16_t checksum = 0;
  struct stat file_stat = {0};

  for (i = 0; i < MAX_USB_PIPES; i++) {
    if (usb_out_pipes[i].type == USB_PIPE_TYPE_BULK) {
      goto found;
    }
  }
  
  res = -1;
  goto not_found;

 found:
  if (!filename) {
    res = -2;
    printf("No file specified.\n");
    goto filename_error;
  }

  retval = stat(filename, &file_stat);
  if (retval) {
    printf("Cannot stat the file.\n");
    goto filestat_error;
  }

  fp = fopen(filename, "r");
  if (!fp) {
    printf("Cannot open the file.\n");
    goto fileopen_error;
  }

  libusb_detach_kernel_driver(usb_out_pipes[i].dev_handle, 
                              usb_out_pipes[i].interface_number);
  libusb_claim_interface(usb_out_pipes[i].dev_handle, 
                         usb_out_pipes[i].interface_number);

  p = data_to_transfer = (unsigned char *)malloc(file_stat.st_size + 10);
  if (!data_to_transfer)
    goto malloc_error;
  pe = data_to_transfer + file_stat.st_size + 10;
  memcpy(p, (unsigned char *)((uint32_t [2])
    {0x30008000, file_stat.st_size + 10}), 8);
  p += 8;

  real_read = fread(p, file_stat.st_size, 1, fp);
  p += real_read;

  for (j = 0; j < real_read; j++) {
    checksum += data_to_transfer[j];
  }
  memcpy(p, (unsigned char *)(&checksum), 2);

  p = data_to_transfer;
  while (p < pe) {
    to_write = (pe - p) < BLOCK_SIZE ? (pe - p) : BLOCK_SIZE;
    retval = libusb_bulk_transfer(usb_out_pipes[i].dev_handle,
                                  usb_out_pipes[i].endpoint,
                                  p, to_write,
                                  &transfered, 3000);
    if (retval) {
      res = -3;
      printf("Transfer error code: %d\n", retval);
      goto transfer_failed;
    }

    p += transfered;
    total_transfered += transfered;
    printf("\r\t %d/%d transfered.", total_transfered, 
           (int)(file_stat.st_size + 10));
  }
  printf("\n");
  
  printf("Transfer finished, total transfered %d bytes, via endpoint=%d.\n", 
         total_transfered, usb_out_pipes[i].endpoint & 0xf);

  free(data_to_transfer);
  libusb_release_interface(usb_out_pipes[i].dev_handle, 
                           usb_out_pipes[i].interface_number);
  libusb_attach_kernel_driver(usb_out_pipes[i].dev_handle, 
                              usb_out_pipes[i].interface_number);
  fclose(fp);

  return 0;

 transfer_failed:
  free(data_to_transfer);
 malloc_error:
  libusb_release_interface(usb_out_pipes[i].dev_handle, 
                           usb_out_pipes[i].interface_number);
  fclose(fp);
 fileopen_error:
 filestat_error:
 filename_error:
 not_found:
  return res;
}

static enum USB_PIPES_TYPE_t 
usb_convert_trans_type_to_pipe(enum libusb_transfer_type type) {
  switch (type) {
  case LIBUSB_TRANSFER_TYPE_CONTROL:
    return USB_PIPE_TYPE_CONTROL;
  case LIBUSB_TRANSFER_TYPE_ISOCHRONOUS:
    return USB_PIPE_TYPE_ISOCHRONOUS;
  case LIBUSB_TRANSFER_TYPE_BULK:
    return USB_PIPE_TYPE_BULK;
  case LIBUSB_TRANSFER_TYPE_INTERRUPT:
    return USB_PIPE_TYPE_INTERRUPT;
  default:
    return USB_PIPE_TYPE_CONTROL;
  }
}

static void usb_device_filter_callback(libusb_device *device)
{
  struct libusb_device_handle *dev_handle;
  struct libusb_device_descriptor device_desc;
  struct libusb_config_descriptor *config_desc;
  const struct libusb_interface_descriptor *interface_desc;
  const struct libusb_endpoint_descriptor *endpoint_desc;
  struct usb_transfer_pipe_t *pipe;
  int retval = 0;
  int i = 0, j = 0, k = 0, l = 0, m = 0, n = 0;

  retval = libusb_get_device_speed(device);
  if (retval < 0 || retval > 4) {
    printf("Cannot get speed of USB device.\nError Code: %d\n", retval);
    goto usb_dev_speed;
  }
  printf("A device matched with speed: %s\n", 
         speed_to_string_tbl[retval]);

  retval = libusb_open(device, &dev_handle);
  if (retval) {
    printf("USB device cannot be opened.\nError Code: %d\n", retval);
    goto usb_open_error;
  }

  retval = libusb_get_device_descriptor(device, &device_desc);
  if (retval < 0) {
    printf("USB device descriptor error.\nError Code: %d\n", retval);
    goto device_desc_error;
  }

  for (i = 0; i < device_desc.bNumConfigurations; i++) {
    retval = libusb_get_config_descriptor(device, i, &config_desc);
    if (retval < 0) {
      printf("USB config descriptor error.\nError Code: %d\n", retval);
      goto config_desc_error;
    }

    for (j = 0; j < config_desc->bNumInterfaces; j++) {
      for (k = 0; k < config_desc->interface[j].num_altsetting; k++) {
        interface_desc = &config_desc->interface[j].altsetting[k];
        for (l = 0; l < interface_desc->bNumEndpoints; l++) {
          endpoint_desc = &interface_desc->endpoint[l];

          switch ((endpoint_desc->bEndpointAddress >> 7) & 0x1) {
          case 1:
            pipe = &usb_in_pipes[m++];
            break;
          case 0:
            pipe = &usb_out_pipes[n++];
            break;
          default:
            printf("Invalid endpoint.\n");
            goto invalid_endpoint;
          }

          pipe->dev_handle = dev_handle;
          pipe->type = usb_convert_trans_type_to_pipe
            (endpoint_desc->bmAttributes & 0x3);
          pipe->endpoint = endpoint_desc->bEndpointAddress;
          pipe->interface_number = interface_desc->bInterfaceNumber;

          printf("Endpoint num:%d, type: %s, dir:%s\n", 
                 endpoint_desc->bEndpointAddress & 0xf,
                 endpoint_type_string_tbl[endpoint_desc->bmAttributes & 0x3],
                 endpoint_dir_string_tbl[(endpoint_desc->bEndpointAddress >> 7) 
                                         & 0x1]);
        }
      }
    }
  }

  retval = usb_device_transfer();
  if (retval) {
    printf("USB transfer error.\nError Code: %d\n", retval);
    goto usb_transfer_error;
  }

  libusb_close(dev_handle);

  return;

 invalid_endpoint:
 usb_transfer_error:
 config_desc_error:
 device_desc_error:
  libusb_close(dev_handle);
 usb_open_error:
 usb_dev_speed:
  return;
}

static int usb_device_filter(enum USB_DEVICE_FILTER_t filter_type,
                             void *filter,
                             libusb_device *device,
                             usb_filter_cb_func_t callback)
{
  int retval = 0, res = 0;
  struct libusb_device_descriptor desc;

  retval = libusb_get_device_descriptor(device, &desc);
  if (retval) {
    printf("Cannot get device descripter, Error Code: %d\n", retval);
    goto device_desc_error;
  }

  switch (filter_type) {
  case USB_DEV_FILTER_BY_PVID:
    if (((struct usb_device_filter_pvid_t *)filter)->vendor_id == 
        desc.idVendor && 
        ((struct usb_device_filter_pvid_t *)filter)->product_id ==
        desc.idProduct) {
      res++;
      callback(device);
    }
    break;
  }

  return res;

 device_desc_error:
  return -1;
}

static struct option long_options[] = {
  {"idVendor",   required_argument, 0,  'v'},
  {"idProduct",  required_argument, 0,  'p'},
  {"help",       no_argument,       0,  'h'},
  {"file",       required_argument, 0,  'f'},
  {0,            0,                 0,   0 }
};

int main(int argc, char *argv[])
{
  int retval = 0;
  char *err;
  int ret = -1;
  libusb_context *context;
  libusb_device **usb_device_list;
  int dev_num = 0;
  int i = 0;
  int opt = 0;
  int option_index = 0; 
  unsigned short idVendor;
  unsigned short idProduct;
  int found = 0;

  while ((opt = getopt_long(argc, argv, "vphf",
                            long_options, &option_index)) != -1) {
    switch (opt) {
    case 'v':
      idVendor = strtol(optarg, &err, 16);
      break;
    case 'p':
      idProduct = strtol(optarg, &err, 16);
      break;
    case 'f':
      if (!optarg) {
        printf("Invaild arguments.\n");
        goto dup_filename;
      }
      filename = strdup(optarg);
      if (!filename) {
        printf("Invaild arguments.\n");
        goto dup_filename;
      }
      break;
    case 'h':
    default:
      goto usage;
    }
  }

  retval = libusb_init(&context);
  if (retval) {
    printf("USB init error\n");
    goto libusb_init_error;
  }
  
  dev_num = libusb_get_device_list(context, &usb_device_list);
  if (dev_num < 0)
    goto libusb_device_list_error;

  for (i = 0; i < dev_num; i++) {
    found += usb_device_filter(USB_DEV_FILTER_BY_PVID, 
                               (void *)&(struct usb_device_filter_pvid_t)
                               {idVendor, idProduct},
                               usb_device_list[i],
                               usb_device_filter_callback);
  }
  
  printf("%d devices processed.\n", found);

  libusb_free_device_list(usb_device_list, 1);
  libusb_exit(context);
  return 0;

 usage:
  printf("\nUsage:\n    dnw-enhanced --idVendor <vendor> --idProduct <product> --file <file>\n    EXAMPLE:\n        dnw-enhanced --idVendor 0x4322 --idProduct 0x5b23 --file program.bin\n\n");
  return 0;

 libusb_device_list_error:
  libusb_exit(context);
 idVendor_invalid:
 idProduct_invalid:
 dup_filename:
 libusb_init_error:
  
  return ret;
}
