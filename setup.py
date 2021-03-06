import setuptools

with open("README.md", "r") as fh:
    long_description = fh.read()

setuptools.setup(
    name="uipath-cloud",
    version="0.0.2",
    author="Andrei Barbu",
    author_email="and.barbu@gmail.com",
    description="UiPath cloud SDK",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/AndreiBarbuOz/uipath-cloud-token",
    packages=setuptools.find_packages(),
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    python_requires='>=3.8'
)