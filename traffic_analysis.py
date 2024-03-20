import dpkt
import pandas as pd
import matplotlib.pyplot as plt
import numpy as np

def plot_features_cdf(list_of_data_tcp, list_of_data_udp, x_label, title):
    """
      Plots a cdf graph of the flows' features.

      Args:
          list_of_data_tcp (list): A list of numeric data about TCP protocol.
          list_of_data_udp (list): A list of numeric data about UDP protocol.
          x_label (string): The label of x-axis.
          title (string): The title of the graph.

      Returns: -
    """

    # Sort the elements of the list
    sorted_data_tcp = np.sort(list_of_data_tcp)
    sorted_data_udp = np.sort(list_of_data_udp)

    # Calculate the cdf
    cdf_tcp = np.cumsum(sorted_data_tcp)
    cdf_udp = np.cumsum(sorted_data_udp)

    # Normalize the values so that they end up ranging between 0 and 1
    norm_cdf_tcp = cdf_tcp / max(cdf_tcp)
    norm_cdf_udp = cdf_udp / max(cdf_udp)

    # Plot the results
    plt.plot(sorted_data_tcp, norm_cdf_tcp, linestyle='-', linewidth=2,
             color='#af49de', label='TCP')
    plt.plot(sorted_data_udp, norm_cdf_udp, linestyle='-', linewidth=2,
             color='#2eb4c9', label='UDP')
    plt.xlabel(x_label)
    plt.ylabel('Cumulative Probability')
    plt.title(title)
    plt.grid(True)
    plt.legend(loc='best')
    plt.show()
    print()

def plot_single_cdf(list_of_data, num_of_bins, x_label, title):
    """
      Plots a cdf graph using a histogram.

      Args:
          list_of_data (list): A list of numeric data.
          num_of_bins (int): The number of bins used in the histogram.
          x_label (string): The label of x-axis.
          title (string): The title of the graph.

      Returns: -
    """

    # Compute the histogram of the data
    values, bins_count = np.histogram(list_of_data, bins=num_of_bins)

    # Calculate the PDF of the histogram using count values
    pdf = values / sum(values)

    # Calculate the CDF from the PDF
    cdf = np.cumsum(pdf)

    # Plotting CDF
    plt.plot(bins_count[1:], cdf, linestyle='-', linewidth=2,
             color='#c9482e')
    plt.xlabel(x_label)
    plt.ylabel('Cumulative Probability')
    plt.title(title)
    plt.grid(True)
    plt.show()
    print()

def plot_barplot(categories, freq, colors, x_label, y_label, title):
    """
      Plots a barplot.

      Args:
          categories (list): A list  of strings.
          freq (list): A list with the number of occurences.
          colors (list): A list with colors.
          x_label (string): The label of x-axis.
          y_label (string): The label for the y-axis.
          title (string): The title of the graph.

      Returns: -
    """

    fig = plt.figure()
    ax = fig.add_axes([0, 0, 1, 1])

    # Add grid behind the bars
    ax.set_axisbelow(True)
    ax.xaxis.grid(color='gray')
    ax.yaxis.grid(color='gray')
    ax.bar(categories, freq, color=colors, width=0.4)

    # Add value labels on bars
    for i in range(len(categories)):
        plt.text(i, freq[i], freq[i], ha='center')

    plt.xlabel(x_label)
    plt.ylabel(y_label)
    plt.title(title)
    plt.show()
    print()

def calc_percentage(first_count, sec_count, third_count, fourth_count, total):
    """
      Calculates percentages.

      Args:
          first_count (int): Number of ocurances of the first category.
          sec_count (int): Number of ocurances of the second category.
          third_count (int): Number of ocurances of the third category.
          fourth_count (int): Number of ocurances of the fourth category.
          total (int): Total number of ocurances.

      Returns:
          first_percent (float): The percentage of the first category.
          sec_percent (float): The percentage of the second category.
          third_percent (float): The percentage of the third category.
          fourth_percent (float): The percentage of the fourth category.
          rest_count (int): The rest number of ocurances.
          rest_percent (float): The percentage of the rest categories.
    """

    # Calculate the percentages of each category
    first_percent = first_count / total * 100
    sec_percent = sec_count / total * 100
    third_percent = third_count / total * 100
    fourth_percent = fourth_count / total * 100

    # Calculate the remaining number of occurences and their percentage
    rest_count = total - (first_count + sec_count + third_count + fourth_count)
    rest_percent = 100 - (first_percent + sec_percent + third_percent + fourth_percent)

    return first_percent, sec_percent, third_percent, fourth_percent, rest_count, rest_percent

def filter_flow_bytes(dict_flows, protocol_num):
    """
      Filters the bytes of the flows which are saved in a dictionary
      which has the form  {key = tuple : value = dictionary}.

      Args:
        dict_flows (dictionary): A dictionary which
          contains the features of the flows.
        protocol_num (int): Each protocol has an assigned internet
          protocol number.

      Returns:
        list_of_bytes (list): A list which has as elements the bytes
          of each packet with the specific protocol.
    """

    # Create a list where the bytes will be saved
    list_of_bytes = []

    for key, value in dict_flows.items():
        for inner_key, inner_value in value.items():
            if inner_key == 'Protocol' and inner_value == protocol_num:
                list_of_bytes.append(value['Number of bytes'])

    return list_of_bytes

def filter_flow_durations(dict_flows, protocol_num):
    """
      Filters the durations of the flows which are saved in a dictionary
      which has the form  {key = tuple : value = dictionary}.

      Args:
        dict_flows (dictionary): A dictionary which
          contains the features of the flows.
        protocol_num (int): Each protocol has an assigned internet
          protocol number.

      Returns:
        list_of_durations (list): A list which has as elements the durations
          of each packet with the specific protocol.
    """

    # Create a list where the durations will be saved
    list_of_durations = []

    for key, value in dict_flows.items():
        for inner_key, inner_value in value.items():
            if inner_key == 'Protocol' and inner_value == protocol_num:
                list_of_durations.append(value['Duration'])

    return list_of_durations

def main():

    filename = 'file.pcap'

    with open(filename, 'rb') as f:
        # Parse the .pcap file
        pcap = dpkt.pcap.Reader(f)

        # Initialize an empty dictionary for the packets
        packets = {}
        # Initialize an empty dictionary for the flows
        flows = {}

        # Count the number of packets
        # This variable will be used as a key in packet's dictionary
        count = 0

        # Initialize variables to store the packet counts for each category
        tcp_count = 0
        udp_count = 0
        arp_count = 0
        icmp_count = 0
        # Initialize variables to store the total number of packets and their total size
        total_count = 0
        total_bytes = 0

        # Initialize an empty list to keep the packets' lengths
        packets_length = []

        # Initialize an empty list to keep the bytes of ARP packets
        list_of_bytes_arp = []

        # Iterate through the packets in the pcap file
        for ts, buf in pcap:

            # Continue with the next packet
            count += 1

            # Append packet's length
            packets_length.append(len(buf))

            # Parse the packet
            eth = dpkt.ethernet.Ethernet(buf)

            # Check if the packet is an IP packet
            if isinstance(eth.data, dpkt.ip.IP):

                # Extract the source and destination IP addresses, the protocol and the port numbers
                src_ip = eth.data.src
                dst_ip = eth.data.dst
                protocol = eth.data.p
                src_port = 0
                dst_port = 0
                # Check if the packet's protocol is TCP
                if protocol == dpkt.ip.IP_PROTO_TCP:
                    tcp = eth.data.data
                    src_port = tcp.sport
                    dst_port = tcp.dport
                    tcp_count += 1
                # Check if the packet's protocol is UDP
                elif protocol == dpkt.ip.IP_PROTO_UDP:
                    udp = eth.data.data
                    src_port = udp.sport
                    dst_port = udp.dport
                    udp_count += 1
                # Check if the packet's protocol is ICMP
                elif protocol == dpkt.ip.IP_PROTO_ICMP:
                    icmp_count += 1
                else:
                    continue

                # Save the information to the packet dictionary
                # Set the 'count' as packet key
                packet_key = count

                packets[packet_key] = {
                    'Source IP': src_ip,
                    'Destination IP': dst_ip,
                    'Source Port': src_port,
                    'Destination Port': dst_port,
                    'Protocol': protocol
                }

                # Create the key for the flows' dictionary
                flow_key = (src_ip, dst_ip, src_port, dst_port)

                if flow_key in flows:
                    flow = flows[flow_key]
                    flow['Number of packets'] += 1
                    flow['Number of bytes'] += len(buf)
                    flow['Last seen'] = ts
                else:
                    flows[flow_key] = {
                        'Number of packets': 1,
                        'Number of bytes': len(buf),
                        'First seen': ts,
                        'Last seen': ts,
                        'Protocol': protocol
                    }

            # An ARP packet is not an IP packet
            # Check if it also contains an ARP packet
            if isinstance(eth.data, dpkt.arp.ARP):
                arp_count += 1
                list_of_bytes_arp.append(len(buf))

        # Total number of packets is equal to the 'count' variable
        total_count = count
        # Total bytes are equal to the sum of bytes of all packets
        total_bytes = sum(packets_length)

        # Print the flow information and calculate the duration of each flow
        for flow_key, flow in flows.items():
            duration = flow['Last seen'] - flow['First seen']
            flow['Duration'] = duration

    # Create the lists of bytes based on their protocol number
    # The list of bytes for the ARP packets has already been calculated
    list_of_bytes_tcp = filter_flow_bytes(flows, 6)
    list_of_bytes_udp = filter_flow_bytes(flows, 17)
    list_of_bytes_icmp = filter_flow_bytes(flows, 1)

    # Summarise the bytes of each protocol
    tcp_bytes = sum(list_of_bytes_tcp)
    udp_bytes = sum(list_of_bytes_udp)
    arp_bytes = sum(list_of_bytes_arp)
    icmp_bytes = sum(list_of_bytes_icmp)

    tcp_bytes_prc, udp_bytes_prc, arp_bytes_prc, icmp_bytes_prc, other_bytes, other_bytes_prc = calc_percentage(
        tcp_bytes, udp_bytes, arp_bytes, icmp_bytes, total_bytes)

    # Create a dictionary of data for the dataframe of bytes
    data_bytes = {'Protocols': ['TCP', 'UDP', 'ARP', 'ICMP', 'Other'],
                  'Count': [tcp_bytes, udp_bytes, arp_bytes, icmp_bytes, other_bytes],
                  'Traffic Volume (%)': [tcp_bytes_prc, udp_bytes_prc, arp_bytes_prc, icmp_bytes_prc, other_bytes_prc]}

    df_bytes = pd.DataFrame(data_bytes)
    print(df_bytes)

    # Calculate the percentage of each protocol in the trace file
    tcp_prc, udp_prc, arp_prc, icmp_prc, other_count, other_prc = calc_percentage(tcp_count, udp_count, arp_count,
                                                                                  icmp_count, total_count)

    # Create a dictionary of data for the dataframe of protocols and their frequency
    data_prot = {'Protocols': ['TCP', 'UDP', 'ARP', 'ICMP', 'Other'],
            'Count': [tcp_count, udp_count, arp_count, icmp_count, other_count],
            'Percent (%)': [tcp_prc, udp_prc, arp_prc, icmp_prc, other_prc]}

    df_prot = pd.DataFrame(data_prot)
    print(df_prot)

    protocols_used = ['TCP', 'UDP', 'ARP', 'ICMP', 'Other protocols']
    freq = [tcp_bytes, udp_bytes, arp_bytes, icmp_bytes, other_bytes]
    color = ['#c9482e', '#32a852', '#2eb4c9', '#af49de', '#dbd81d']

    # Create a barplot which represents the frequency of traffic protocols
    plot_barplot(protocols_used, freq, color,
                 'Protocols', 'Number of Bytes', 'Traffic Volume per Protocol')

    freq = [tcp_count, udp_count, arp_count, icmp_count, other_count]
    color = ['#c9482e', '#32a852', '#2eb4c9', '#af49de', '#dbd81d']

    # Create a barplot which represents the frequency of traffic protocols
    plot_barplot(protocols_used, freq, color,
                 'Protocols', 'Number of Packets', 'Frequency of Protocols')

    # Visualize the total packet size distribution using a cdf graph
    plot_single_cdf(packets_length, 50, 'Packet Size', 'Total packet size distribution from all flows')

    # Create the list of durations for the cdf graphs based on their protocol number
    list_of_durations_tcp = filter_flow_durations(flows, 6)
    list_of_durations_udp = filter_flow_durations(flows, 17)

    # Create a cdf graph for the flow size
    plot_features_cdf(list_of_bytes_tcp, list_of_bytes_udp,
                      'Flow Size (bytes)', 'CDF of Flow Size')

    # Create a cdf graph fot the flow duration
    plot_features_cdf(list_of_durations_tcp, list_of_durations_udp,
                      'Duration (sec)', 'CDF of Flow Duration')

if __name__ == '__main__':
    main()