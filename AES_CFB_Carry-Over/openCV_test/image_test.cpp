#include "aes_cfb.h"

#include <opencv2/core/core.hpp>
#include <opencv2/highgui/highgui.hpp>
#include <opencv2/imgproc/imgproc.hpp>

#include <iostream>
#include <unistd.h>

#define BLOCKSIZE 16
void serialize(u8 *out, cv::Mat *in, int size)
{
	for (int h = 0; h < in->rows; h++)
	{
		for (int w = 0; w < in->cols; w++)
		{
			*out = (*in).at<u8>(h,w); out++;
		}
	}
	/*
	//int size = (*in).total() * (*in).elemSize();
	std::cout << "Plaintext size: " << size << std::endl;
	u8 *tmp = (u8*)in;
	std::cout << "Serializing\n";
	for (int i = 0; i < size; i++)
		*out = *tmp; out++; tmp++;
	std::cout << "Done serializing\n";*/
}

void deserialize(cv::Mat *out, u8 *in, int size)
{
	for (int h = 0; h < out->rows; h++)
	{
		for (int w = 0; w < out->cols; w++)
		{
			(*out).at<u8>(h,w) = *in; in++;
		}
	}
	/*
	//int size = (*out).total() * (*out).elemSize();
	std::cout << "Encrypted size: " << size << std::endl;
	u8 *tmp = (u8*)out;
	std::cout << "Deserializing\n";
	for (int i = 0; i < size; i++)
		*tmp = *in; tmp++; in++;
	std::cout << "Done serializing\n";*/
}

int main()
{
	std::string imagePath = "/home/pi/EncryptionLaboratory/aes/self_made_cfb/openCV_test/bird.jpg";
	cv::Mat image, greyImage;
	image = cv::imread(imagePath, cv::IMREAD_COLOR);

	std::cout << "# original channels: " << image.channels() << std::endl;
	// Display original image
	cv::imshow( "Original image", image );
	cv::waitKey(2000);

	// convert to greyscale
	cv::cvtColor( image, greyImage, cv::COLOR_BGR2GRAY );

	std::cout << "# grayscale channels: " << greyImage.channels() << std::endl;
	std::cout << "Grayscale type: " << greyImage.type() << std::endl;

	cv::imshow( "Grey image", greyImage );
	cv::waitKey(2000);

	u8 key[BLOCKSIZE] = {0};
	u32 iv[BLOCKSIZE/4] = {0};

	cipher_state e_cs;

	cfb_initialize_cipher(&e_cs, key, iv);


	int size = greyImage.total() * greyImage.elemSize();
	u8 plaintext[size];

	if (greyImage.isContinuous())
		serialize(plaintext, &greyImage, size);

	cv::Mat deserialized = cv::Mat::zeros(cv::Size(greyImage.cols, greyImage.rows), CV_8U);
	deserialize(&deserialized, plaintext, size);

	cv::imshow( "Deserialized image", deserialized);
	cv::waitKey(2000);

	u8 ciphertext[size];

	cv::Mat encrypted = cv::Mat::zeros(cv::Size(greyImage.cols, greyImage.rows), CV_8U);

	std::cout << "Is continuous encrypted: " << encrypted.isContinuous() << std::endl;
	cfb_process_packet(&e_cs, plaintext, ciphertext, size, ENCRYPT);
	
	deserialize(&encrypted, ciphertext, size);

	cv::imshow( "Encrypted image", encrypted );
	cv::waitKey(2000);

	// RECOVER
	cipher_state d_cs;
	cfb_initialize_cipher(&d_cs, key, iv);

	u8 deciphered[size];

	cfb_process_packet(&d_cs, ciphertext, deciphered, size, DECRYPT);

	cv::Mat decrypted = cv::Mat::zeros(cv::Size(greyImage.cols, greyImage.rows), CV_8UC1);

	deserialize(&decrypted, deciphered, size);

	cv::imshow( "Recovered image", decrypted );
	cv::waitKey(5000);
/*	std::cout << "Before encryption\n";
	cfb_process_packet(&e_cs, (u8*)&greyImage, ciphertext, size, ENCRYPT);
	std::cout << "After encryption\n";

	cv::Mat encrypted;
	std::memcpy((void*)&encrypted, (const void*)ciphertext, size);
	cv::imshow( "Encrypted image", encrypted );
*/
}
