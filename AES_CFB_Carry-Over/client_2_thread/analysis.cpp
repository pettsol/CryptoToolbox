#include <iostream>
#include <fstream>
#include <cmath>

int main(int argc, char **argv)
{
	if (argc != 2) exit(1);
	std::ifstream log(argv[1]);
	
	double sum = 0;
	double n_numbers = 0;
	int sampleNr = 0;
	double tmp = 0;
	double variance = 0;
	int count = 0;
	while (log >> tmp)
	{
		if ( count++ < 3 ) continue;
		n_numbers++;
		if (n_numbers < 1000)
		{
			continue;
		}
		sum += tmp;
		sampleNr++;
	}
	double mean = sum / sampleNr;

	// Reset to first line
	log.clear();
	log.seekg(0, std::ios::beg);
	
	count = 0;
	while (log >> tmp)
	{
		if ( count++ < 3 ) continue;
		variance += std::pow(tmp - mean, 2);
	}
	variance = variance / sampleNr;
	double stdDeviation = std::sqrt(variance);

	std::cout << "Mean: " << mean << " microseconds"  << std::endl;
	std::cout << "StdDev: " << stdDeviation << " microseconds" << std::endl;
	std::cout << "Number of samples: " << sampleNr << std::endl;
}
