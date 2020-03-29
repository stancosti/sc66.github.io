/**
 * @brief
 * @version
 * @author
 * @copyright
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 *
 */

#include "web_client.h"
#include <iostream>

using namespace std;

int main(int argc, char *argv[])
{
    const char lServiceUrl[31] = "wss://ws-feed.pro.coinbase.com";
    const char lSymbol[8] = "BTC-USD";
    const char *lServiceLevel = nullptr; // "full" "level2";

    char key[10];
    key[0] = '\0';

    try
    {
        sWS::WebClient lClient;

        //  Format the subscribe request message
        char lSubscribeREQ[100];
        if (lServiceLevel)
        {
            sprintf(lSubscribeREQ, "{\"type\":\"subscribe\", \"product_ids\":[\"%s\"], \"channels\":[\"%s\"]}", lSymbol, lServiceLevel);
        }
        else
        {
            // sprintf(lSubscribeREQ, "{\"type\":\"subscribe\", \"product_ids\":[\"BTC-USD\",\"ETH-USD\"], \"channels\":[\"level2\",\"full\"]}");
            sprintf(lSubscribeREQ, "{\"type\":\"subscribe\", \"product_ids\":[\"%s\"], \"channels\":[\"level2\",\"full\"]}", lSymbol);
        }

        //  Subscribe for market data (blocking mode)
        lClient.subscribe(lServiceUrl, lSubscribeREQ, 3000, 3, 5000);

        //  Wait for user input
        cout << "Press ENTER to STOP.." << endl;
        cin.getline(key, 1);
    }
    catch (std::logic_error &e1)
    {
        cout << endl
             << endl
             << "LOGIC ERROR: " << e1.what()
             << endl
             << "The program will be terminated.";
    }
    catch (std::runtime_error &e2)
    {
        cout << endl
             << endl
             << "RUNTIME ERROR: " << e2.what()
             << endl
             << "The program will be terminated.";
    }
    catch (std::exception &e0)
    {
        cout << endl
             << endl
             << "STD ERROR: " << e0.what()
             << endl
             << "The program will be terminated.";
    }
}