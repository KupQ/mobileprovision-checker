# Provision Checker

A Python-based tool to check the validity of Apple provisioning profiles by extracting certificates, verifying OCSP status, and checking entitlements. The tool is separated into modular Python files to follow clean code principles.

### Clone the Repository

```bash
git clone https://github.com/KupQ/mobileprovision-checker.git
cd mobileprovision-checker
```

### Prerequisites

- Python 3.8 or higher
- Pip (Python package installer)

## Installation

```bash
pip install --upgrade -r requirements.txt

```

## Usage

```bash
python3 main.py yourfile.mobileprovision

```
```bash
python3 main.py youfile.p12 password

```
```bash
python3 main.py youfile.p12 oldpass Newpass output.p12

```

- Help
```bash
python3 main.py

```


## License

licensed under the terms of  BSD-3-Clause license. See the [LICENSE](LICENSE) file.

> THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
