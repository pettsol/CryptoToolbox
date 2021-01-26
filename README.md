*********************************************************************************************************************

This toolbox contain C-style C++ implementations of
cryptographical algorithms. All implementations have
been verified by official test vectors, and are provided
as-is.

The toolbox is described in detail in https://www.mic-journal.no/ABS/MIC-2020-4-3.asp/

Please cite the repository as:

Petter Solnør, (2020), “A Cryptographic Toolbox for Feedback Control Systems”

bibtex entry:

@article{MIC-2020-4-3,
  title={{A Cryptographic Toolbox for Feedback Control Systems}},
  author={Solnør, Petter},
  journal={Modeling, Identification and Control},
  volume={41},
  number={4},
  pages={313--332},
  year={2020},
  doi={10.4173/mic.2020.4.3},
  publisher={Norwegian Society of Automatic Control}
};

All algorithms take a pointer to an input buffer
and a pointer to an output buffer. It is the users task
to serialize the data into the input buffers, and
deserialize the data from the output buffers.

The size of the input buffer is also required as input.

All source code is available, and I hereby declare
that no hidden backdoors have been added to the code.


Petter Solnoer - 26/01/2020.

*********************************************************************************************************************
